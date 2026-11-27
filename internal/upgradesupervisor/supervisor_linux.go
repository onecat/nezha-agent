//go:build linux

// Package upgradesupervisor coordinates verified local upgrades. Network
// authorization and the concrete worker health transport are separate.
package upgradesupervisor

import (
 "context"
 "crypto/ed25519"
 "errors"
 "io"
 "sync"
 "time"

 "github.com/onecat/nezha-agent/internal/upgradeinstall"
 "github.com/onecat/nezha-agent/internal/upgradestate"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

const operationTimeout=30*time.Second

// Worker belongs exclusively to the local supervisor. Stop must confirm
// termination (and be idempotent); Start must launch only the configured
// local executable, and Healthy must prove readiness of that exact new
// process, not an old Dashboard heartbeat or a version string alone.
// All operations must honor their context deadlines.
type Worker interface {
 Stop(context.Context)error
 Start(context.Context)error
 Healthy(context.Context,string)error
}

type Supervisor struct{
 mu sync.Mutex
 state *upgradestate.Store
 installer *upgradeinstall.Installer
 worker Worker
}

func New(state *upgradestate.Store,dir string,worker Worker)(*Supervisor,error){
 if worker==nil{return nil,errors.New("missing local worker")}
 installer,err:=upgradeinstall.New(dir,state)
 if err!=nil{return nil,err}
 return &Supervisor{state:state,installer:installer,worker:worker},nil
}

func bounded(ctx context.Context,fn func(context.Context)error)error{
 c,cancel:=context.WithTimeout(ctx,operationTimeout)
 defer cancel()
 if err:=c.Err();err!=nil{return err}
 if err:=fn(c);err!=nil{return err}
 return c.Err()
}

func(s *Supervisor) startHealthy(ctx context.Context,version string)error{
 if version==""{return errors.New("missing expected worker version")}
 if err:=bounded(ctx,s.worker.Start);err!=nil{return err}
 return bounded(ctx,func(c context.Context)error{return s.worker.Healthy(c,version)})
}

func(s *Supervisor) task(expected core.Transaction)(core.Transaction,error){
 _,t,err:=s.state.Snapshot()
 if err!=nil{return core.Transaction{},err}
 if t==nil||!t.SameIdentity(expected)||!t.ExpiresAt.Equal(expected.ExpiresAt){
  return core.Transaction{},errors.New("unexpected durable task")
 }
 return *t,nil
}

// Apply accepts only an already authorized and durably reserved task.
// oldVersion must come from trusted local supervisor state, never the
// incoming upgrade request. The caller owns the immutable verified archive.
// Cancellation or expiry after the swap triggers bounded local rollback;
// rollback is deliberately independent of the network/task context.
func(s *Supervisor) Apply(ctx context.Context,expected core.Transaction,r io.ReaderAt,size int64,keys map[string]ed25519.PublicKey,oldVersion string)(core.Transaction,error){
 s.mu.Lock();defer s.mu.Unlock()
 t,err:=s.task(expected)
 if err!=nil{return t,err}
 if expected.State!=core.StateVerified||t.State!=core.StateVerified||oldVersion==""||oldVersion==t.Version{
  return t,errors.New("invalid supervisor upgrade request")
 }
 current,previous,_,err:=s.state.VersionInfo()
 if err!=nil||current!=oldVersion||previous!=oldVersion{return t,errors.Join(err,errors.New("rollback version does not match durable ledger"))}
 if err:=ctx.Err();err!=nil{return t,err}
 if !time.Now().Before(t.ExpiresAt){return t,errors.New("expired upgrade")}
 taskCtx,cancel:=context.WithDeadline(ctx,t.ExpiresAt)
 defer cancel()
 if err:=bounded(taskCtx,s.worker.Stop);err!=nil{return t,err}
 if err:=taskCtx.Err();err!=nil{return s.recoverFailure(t,oldVersion,err)}
 next,err:=s.installer.Install(t,r,size,keys,time.Now())
 if err!=nil{return s.recoverFailure(t,oldVersion,err)}
 if next.State!=core.StateHealthCheck{return s.recoverFailure(t,oldVersion,errors.New("unexpected install state"))}
 if err:=s.startHealthy(taskCtx,t.Version);err!=nil{return s.recoverFailure(t,oldVersion,err)}
 if err:=taskCtx.Err();err!=nil{return s.recoverFailure(t,oldVersion,err)}
 done,err:=s.state.Advance(next,core.StateSucceeded,time.Now())
 if err!=nil{return s.recoverFailure(t,oldVersion,err)}
 return done,nil
}

// Recover must run before any ordinary worker launch after supervisor restart.
// Verified tasks are abandoned rather than resumed automatically. A crashed
// installation or health check must restore and check the old binary. Other
// terminal/no-task cases are left to normal service startup.
func(s *Supervisor) Recover(oldVersion string)(core.Transaction,error){
 s.mu.Lock();defer s.mu.Unlock()
 _,t,err:=s.state.Snapshot()
 if err!=nil{return core.Transaction{},err}
 if t==nil{return core.Transaction{},nil}
 switch t.State{
 case core.StateVerified,core.StateInstalling,core.StateHealthCheck,core.StateRollingBack:
  return s.recover(*t,oldVersion)
 default:return *t,nil
 }
}

func(s *Supervisor) recoverFailure(expected core.Transaction,oldVersion string,cause error)(core.Transaction,error){
 t,err:=s.task(expected)
 if err!=nil{
  // An ambiguous state write must not be guessed. Stop any new worker,
  // keep the backup and require reopen/recovery by the local supervisor.
  stopErr:=bounded(context.Background(),s.worker.Stop)
  return t,errors.Join(cause,err,stopErr)
 }
 out,err:=s.recover(t,oldVersion)
 return out,errors.Join(cause,err)
}

func(s *Supervisor) recover(t core.Transaction,oldVersion string)(core.Transaction,error){
 current,previous,_,err:=s.state.VersionInfo()
 if err!=nil||oldVersion==""||oldVersion==t.Version||oldVersion!=current||oldVersion!=previous{return t,errors.Join(err,errors.New("missing or mismatched trusted rollback version"))}
 ctx,cancel:=context.WithTimeout(context.Background(),3*operationTimeout)
 defer cancel()
 if err:=bounded(ctx,s.worker.Stop);err!=nil{return t,err}
 switch t.State{
 case core.StateVerified:
  // No rename can precede the durable installing state. Retain any orphan
  // backup for operator reconciliation and restart the unchanged worker.
  if err:=s.startHealthy(ctx,oldVersion);err!=nil{
   return t,errors.Join(err,bounded(context.Background(),s.worker.Stop))
  }
  done,err:=s.state.Advance(t,core.StateFailed,time.Now())
  if err!=nil{return done,errors.Join(err,bounded(context.Background(),s.worker.Stop))}
  return done,nil
 case core.StateInstalling,core.StateHealthCheck,core.StateRollingBack:
  back,err:=s.installer.Restore(t,time.Now())
  if err!=nil{return back,err}
  if err:=s.startHealthy(ctx,oldVersion);err!=nil{
   return back,errors.Join(err,bounded(context.Background(),s.worker.Stop))
  }
  // Keep rolling_back on failure; do not claim success before the restored
  // worker has passed the independent health contract.
  done,err:=s.state.Advance(back,core.StateRolledBack,time.Now())
  if err!=nil{return done,errors.Join(err,bounded(context.Background(),s.worker.Stop))}
  return done,nil
 default:return t,errors.New("unexpected recovery state")
 }
}

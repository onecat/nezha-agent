//go:build linux

// Package managedupgrade joins the authenticated transport to the local
// Linux supervisor. Production startup and polling are not wired here.
package managedupgrade

import (
 "context"
 "crypto/ed25519"
 "errors"
 "runtime"
 "sync"
 "time"

 "github.com/onecat/nezha-agent/internal/dashboard"
 "github.com/onecat/nezha-agent/internal/upgradestate"
 "github.com/onecat/nezha-agent/internal/upgradesupervisor"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

type Runner struct{
 mu sync.Mutex
 client *dashboard.Client
 state *upgradestate.Store
 supervisor *upgradesupervisor.Supervisor
 serverID uint64
 stageDir string
 keys map[string]ed25519.PublicKey
}
func New(enabled bool,c *dashboard.Client,s *upgradestate.Store,supervisor *upgradesupervisor.Supervisor,serverID uint64,stageDir string,keys map[string]ed25519.PublicKey)(*Runner,error){
 if !enabled||c==nil||s==nil||supervisor==nil||serverID==0||len(keys)==0||(runtime.GOARCH!="amd64"&&runtime.GOARCH!="arm64"){return nil,errors.New("managed upgrade not provisioned")}
 copyKeys:=make(map[string]ed25519.PublicKey,len(keys))
 for id,k:=range keys{
  if id==""||len(k)!=ed25519.PublicKeySize{return nil,errors.New("invalid signing key")}
  copyKeys[id]=append(ed25519.PublicKey(nil),k...)
 }
 return &Runner{client:c,state:s,supervisor:supervisor,serverID:serverID,stageDir:stageDir,keys:copyKeys},nil
}
func terminal(t core.Transaction)bool{
 switch t.State{case core.StateSucceeded,core.StateRolledBack,core.StateFailed:return true};return false
}

// RunOnce requires a trusted local current version and a healthy owned
// worker. Startup recovery must precede it. A previous terminal receipt
// must have been reconciled by the caller before a new run is attempted.
func(r *Runner) RunOnce(ctx context.Context,currentVersion string)(core.Transaction,error){
 r.mu.Lock();defer r.mu.Unlock()
 var zero core.Transaction
 high,prior,err:=r.state.Snapshot()
 if err!=nil{return zero,err}
 if prior!=nil&&!terminal(*prior){return *prior,errors.New("local recovery required")}
 d,err:=r.client.DownloadUpgrade(ctx,r.stageDir,r.serverID,currentVersion,"linux",runtime.GOARCH,high,r.keys)
 if err!=nil{return zero,err}
 defer d.Close()
 t:=d.Task()
 if err:=r.client.AcknowledgeVerified(ctx,d);err!=nil{return t,err}
 if err:=r.state.ReserveVerified(t,d.Package(),"linux",runtime.GOARCH,currentVersion,time.Now());err!=nil{return t,err}
 // No install until both the durable local reservation and an affirmative
 // one-use Dashboard grant exist. An uncertain grant leaves the old worker
 // untouched and consumes the reserved sequence conservatively.
 if err:=r.client.RequestInstallGrant(ctx,d);err!=nil{
  failed,saveErr:=r.state.Advance(t,core.StateFailed,time.Now())
  if saveErr!=nil{return t,errors.Join(err,saveErr)}
  return failed,errors.Join(err,r.report(failed))
 }
 outcome,applyErr:=r.supervisor.Apply(ctx,t,d,d.Size(),r.keys,currentVersion)
 // Never report a transient or guessed terminal state. Reload the ledger;
 // a failed persistence/rollback must remain active for reconciliation.
 _,saved,err:=r.state.Snapshot()
 if err!=nil{return outcome,errors.Join(applyErr,err)}
 if saved==nil||!saved.SameIdentity(t){return outcome,errors.Join(applyErr,errors.New("local result missing"))}
 if !terminal(*saved){return *saved,errors.Join(applyErr,errors.New("upgrade remains unresolved"))}
 return *saved,errors.Join(applyErr,r.report(*saved))
}
func(r *Runner) report(t core.Transaction)error{
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 return r.client.ReportUpgradeResult(ctx,t)
}

// RetryResult only resends the exact latest durable terminal observation;
// it never repeats installation. The caller must retain the ledger until
// the result is acknowledged. A rejected/late claim requires reconciliation.
func(r *Runner) RetryResult()error{
 r.mu.Lock();defer r.mu.Unlock()
 _,t,err:=r.state.Snapshot()
 if err!=nil{return err}
 if t==nil||!terminal(*t){return errors.New("no terminal result to retry")}
 return r.report(*t)
}

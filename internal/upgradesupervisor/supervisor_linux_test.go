//go:build linux

package upgradesupervisor

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "runtime"
 "testing"
 "time"

 "github.com/onecat/nezha-agent/internal/upgradestate"
 "github.com/onecat/nezha-agent/internal/upgradeinstall"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

// File replacement and ledger are real; this worker is intentionally a
// deterministic test double, not evidence of actual process readiness.
type workerFixture struct{
 target string
 running bool
 badNew bool
 badOld bool
 cancel context.CancelFunc
}
func(w *workerFixture) Stop(ctx context.Context)error{
 if err:=ctx.Err();err!=nil{return err}
 w.running=false
 return nil
}
func(w *workerFixture) Start(ctx context.Context)error{
 if err:=ctx.Err();err!=nil{return err}
 if w.running{return errors.New("already running")}
 w.running=true
 return nil
}
func(w *workerFixture) Healthy(ctx context.Context,version string)error{
 if err:=ctx.Err();err!=nil{return err}
 b,err:=os.ReadFile(w.target)
 if err!=nil{return err}
 if !w.running||string(b)!=version{return errors.New("wrong worker")}
 if version=="v0.30.01"&&w.cancel!=nil{w.cancel();return ctx.Err()}
 if (version=="v0.30.01"&&w.badNew)||(version=="v0.30.00"&&w.badOld){return errors.New("unhealthy fixture")}
 return nil
}

type fixture struct{
 state *upgradestate.Store
 worker *workerFixture
 dir,stateDir string
 task core.Transaction
 archive []byte
 keys map[string]ed25519.PublicKey
}
func setup(t *testing.T)fixture{
 t.Helper()
 dir:=t.TempDir()
 stateDir:=filepath.Join(dir,"state")
 if err:=os.Mkdir(stateDir,0700);err!=nil{t.Fatal(err)}
 target:=filepath.Join(dir,"nezha-agent")
 if err:=os.WriteFile(target,[]byte("v0.30.00"),0700);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 keys:=map[string]ed25519.PublicKey{"fixture":pub}
 var archive bytes.Buffer
 b:=[]byte("v0.30.01")
 m:=core.Manifest{Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:"linux",Arch:runtime.GOARCH,SigningKeyID:"fixture",ReleaseSequence:2}
 if _,err:=core.BuildPackage(&archive,bytes.NewReader(b),int64(len(b)),m,priv);err!=nil{t.Fatal(err)}
 p,err:=core.VerifyPackage(bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys)
 if err!=nil{t.Fatal(err)}
 now:=time.Now()
 task:=core.Transaction{ID:"fixture",ServerID:42,PackageSHA256:p.PackageSHA256,Version:m.Version,ReleaseSequence:2,State:core.StateVerified,ExpiresAt:now.Add(time.Minute)}
 state,err:=upgradestate.Initialize(stateDir,42,1)
 if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){state.Close()})
 if err:=state.ReserveVerified(task,p,"linux",runtime.GOARCH,"v0.30.00",now);err!=nil{t.Fatal(err)}
 return fixture{state:state,worker:&workerFixture{target:target,running:true},dir:dir,stateDir:stateDir,task:task,archive:archive.Bytes(),keys:keys}
}
func TestApplyHealthAndRollback(t *testing.T){
 for _,mode:=range []string{"success","bad-new","cancel","bad-old","bad-signature"}{
  t.Run(mode,func(t *testing.T){
   f:=setup(t)
   ctx,cancel:=context.WithCancel(context.Background())
   defer cancel()
   keys:=f.keys
   want:=core.StateSucceeded
   switch mode{
   case "bad-new":f.worker.badNew=true;want=core.StateRolledBack
   case "cancel":f.worker.cancel=cancel;want=core.StateRolledBack
   case "bad-old":f.worker.badNew=true;f.worker.badOld=true;want=core.StateRollingBack
   case "bad-signature":keys=nil;want=core.StateFailed
   }
   s,err:=New(f.state,f.dir,f.worker)
   if err!=nil{t.Fatal(err)}
   got,err:=s.Apply(ctx,f.task,bytes.NewReader(f.archive),int64(len(f.archive)),keys,"v0.30.00")
   if (err==nil)!=(mode=="success")||got.State!=want{t.Fatalf("state %s error %v; want %s",got.State,err,want)}
   seq,durable,err:=f.state.Snapshot()
   if err!=nil||seq!=2||durable==nil||durable.State!=want{t.Fatal("invalid durable result",err)}
   if f.worker.running!=(mode!="bad-old"){t.Fatal("incorrect worker running state")}
   b,err:=os.ReadFile(f.worker.target)
   expected:="v0.30.00"
   if mode=="success"{expected="v0.30.01"}
   if err!=nil||string(b)!=expected{t.Fatal("incorrect installed bytes",err)}
  })
 }
}
func TestRecoverInterruptedHealthCheck(t *testing.T){
 f:=setup(t)
 i,err:=upgradeinstall.New(f.dir,f.state)
 if err!=nil{t.Fatal(err)}
 if _,err:=i.Install(f.task,bytes.NewReader(f.archive),int64(len(f.archive)),f.keys,time.Now());err!=nil{t.Fatal(err)}
 if err:=f.state.Close();err!=nil{t.Fatal(err)}
 reopened,err:=upgradestate.Open(f.stateDir,42)
 if err!=nil{t.Fatal(err)}
 defer reopened.Close()
 f.worker.running=false
 s,err:=New(reopened,f.dir,f.worker)
 if err!=nil{t.Fatal(err)}
 got,err:=s.Recover("v0.30.00")
 if err!=nil||got.State!=core.StateRolledBack||!f.worker.running{t.Fatal("recovery failed",got,err)}
}

func TestRejectMismatchedRollbackVersionBeforeStopping(t *testing.T){
 f:=setup(t)
 s,err:=New(f.state,f.dir,f.worker)
 if err!=nil{t.Fatal(err)}
 if _,err:=s.Apply(context.Background(),f.task,bytes.NewReader(f.archive),int64(len(f.archive)),f.keys,"v0.29.99");err==nil{t.Fatal("mismatched local version accepted")}
 if !f.worker.running{t.Fatal("worker stopped before version validation")}
 if _,err:=s.Recover("v0.29.99");err==nil{t.Fatal("mismatched recovery version accepted")}
 if !f.worker.running{t.Fatal("worker stopped before recovery validation")}
 _,durable,err:=f.state.Snapshot()
 if err!=nil||durable==nil||durable.State!=core.StateVerified{t.Fatal("ledger changed",err)}
}

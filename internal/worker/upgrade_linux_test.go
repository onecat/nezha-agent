//go:build linux

package worker

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "os"
 "os/exec"
 "path/filepath"
 "runtime"
 "testing"
 "time"

 "github.com/onecat/nezha-agent/internal/upgradestate"
 "github.com/onecat/nezha-agent/internal/upgradestage"
 "github.com/onecat/nezha-agent/internal/upgradesupervisor"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

func buildVersion(t *testing.T,version string)[]byte{
 t.Helper()
 path:=filepath.Join(t.TempDir(),"nezha-agent")
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Minute)
 defer cancel()
 cmd:=exec.CommandContext(ctx,"go","build","-mod=mod","-ldflags=-X main.version="+version,"-o",path,"../../cmd/agent")
 if b,err:=cmd.CombinedOutput();err!=nil{t.Fatalf("build: %v %s",err,b)}
 b,err:=os.ReadFile(path)
 if err!=nil{t.Fatal(err)}
 return b
}

// Runs two actual Agent executables, built from this development tree with
// distinct version labels. This is a local integration test, not a release
// qualification of independently published versions or the Dashboard process.
func TestRealSignedUpgradeAndRollback(t *testing.T){
 oldBinary:=buildVersion(t,"v0.30.00")
 newBinary:=buildVersion(t,"v0.30.02")
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 keys:=map[string]ed25519.PublicKey{"integration":pub}
 manifest:=core.Manifest{Version:"v0.30.02",MinAgentVersion:"v0.30.00",OS:"linux",Arch:runtime.GOARCH,SigningKeyID:"integration",ReleaseSequence:2}
 var archive bytes.Buffer
 if _,err:=core.BuildPackage(&archive,bytes.NewReader(newBinary),int64(len(newBinary)),manifest,priv);err!=nil{t.Fatal(err)}
 signed,err:=core.VerifyPackage(bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys)
 if err!=nil{t.Fatal(err)}
 for _,mode:=range []string{"success","reject-new-health"}{
  t.Run(mode,func(t *testing.T){
   dir:=t.TempDir()
   if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
   target:=filepath.Join(dir,"nezha-agent")
   if err:=os.WriteFile(target,oldBinary,0700);err!=nil{t.Fatal(err)}
   stateDir:=filepath.Join(dir,"state")
   if err:=os.Mkdir(stateDir,0700);err!=nil{t.Fatal(err)}
   state,err:=upgradestate.Initialize(stateDir,42,1)
   if err!=nil{t.Fatal(err)}
   defer state.Close()
   config,fixture:=localReporter(t,dir)
   fixture.allowNext.Store(true)
   fixture.rejectNext.Store(mode=="reject-new-health")
   p,err:=New(dir,config)
   if err!=nil{t.Fatal(err)}
   defer func(){ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel();if err:=p.Stop(ctx);err!=nil{t.Error(err)}}()
   ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second)
   defer cancel()
   if err:=p.Start(ctx);err!=nil{t.Fatal(err)}
   if err:=p.Healthy(ctx,"v0.30.00");err!=nil{t.Fatal(err)}
   now:=time.Now()
   task:=core.Transaction{ID:"integration-"+mode,ServerID:42,PackageSHA256:signed.PackageSHA256,Version:manifest.Version,ReleaseSequence:2,State:core.StateTransferring,ExpiresAt:now.Add(time.Minute)}
   stage,err:=upgradestage.New(dir,task,int64(archive.Len()),now)
   if err!=nil{t.Fatal(err)}
   defer stage.Close()
   sender,err:=core.NewSender(task,bytes.NewReader(archive.Bytes()),int64(archive.Len()))
   if err!=nil{t.Fatal(err)}
   var offset int64
   for{
    chunk,done,err:=sender.ChunkAt(offset)
    if err!=nil{t.Fatal(err)}
    if done{break}
    if err:=stage.WriteChunk(chunk,time.Now());err!=nil{t.Fatal(err)}
    offset+=int64(len(chunk.Data))
   }
   verified,err:=stage.Seal(keys,"linux",runtime.GOARCH,"v0.30.00",1,time.Now())
   if err!=nil{t.Fatal(err)}
   task,err=task.Transition(core.StateVerified,time.Now())
   if err!=nil{t.Fatal(err)}
   if err:=state.ReserveVerified(task,verified,"linux",runtime.GOARCH,"v0.30.00",time.Now());err!=nil{t.Fatal(err)}
   supervisor,err:=upgradesupervisor.New(state,dir,p)
   if err!=nil{t.Fatal(err)}
   applyCtx:=ctx
   if mode!="success"{
    var stop context.CancelFunc
    applyCtx,stop=context.WithTimeout(ctx,8*time.Second)
    defer stop()
   }
   out,err:=supervisor.Apply(applyCtx,task,stage,int64(archive.Len()),keys,"v0.30.00")
   expected:=newBinary
   wantState:=core.StateSucceeded
   wantVersion:="v0.30.02"
   if mode!="success"{
    expected=oldBinary;wantState=core.StateRolledBack;wantVersion="v0.30.00"
   }
   if out.State!=wantState||(err==nil)!=(mode=="success"){t.Fatalf("apply: state=%s err=%v",out.State,err)}
   high,snapshot,err:=state.Snapshot()
   if err!=nil||high!=2||snapshot==nil||snapshot.State!=wantState{t.Fatal("durable outcome mismatch",err)}
   got,err:=os.ReadFile(target)
   if err!=nil||!bytes.Equal(got,expected){t.Fatal("installed executable mismatch",err)}
   if err:=p.Healthy(ctx,wantVersion);err!=nil{t.Fatal("restored or upgraded worker not healthy",err)}
   if fixture.nextActive.Load()!=(mode=="success"){t.Fatal("unexpected active reporter version")}
   if err:=p.Stop(ctx);err!=nil{t.Fatal(err)}
   if err:=state.Close();err!=nil{t.Fatal(err)}
   reopened,err:=upgradestate.Open(stateDir,42)
   if err!=nil{t.Fatal(err)}
   defer reopened.Close()
   high,snapshot,err=reopened.Snapshot()
   if err!=nil||high!=2||snapshot==nil||snapshot.State!=wantState{t.Fatal("outcome lost on reopen",err)}
   if err:=verified.Manifest.CheckUpgrade("linux",runtime.GOARCH,"v0.30.00",high);err==nil{t.Fatal("replay accepted")}
  })
 }
}

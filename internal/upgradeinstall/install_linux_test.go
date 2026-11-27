//go:build linux

package upgradeinstall

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "os"
 "path/filepath"
 "runtime"
 "testing"
 "time"

 "github.com/onecat/nezha-agent/internal/upgradestate"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

func TestInstallRestoreAfterRestart(t *testing.T){
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 stateDir:=filepath.Join(dir,"state")
 if err:=os.Mkdir(stateDir,0700);err!=nil{t.Fatal(err)}
 target:=filepath.Join(dir,executable)
 if err:=os.WriteFile(target,[]byte("old worker fixture"),0700);err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 keys:=map[string]ed25519.PublicKey{"test":pub}
 body:=[]byte("new worker fixture")
 var archive bytes.Buffer
 m:=core.Manifest{Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:"linux",Arch:runtime.GOARCH,SigningKeyID:"test",ReleaseSequence:2}
 if _,err:=core.BuildPackage(&archive,bytes.NewReader(body),int64(len(body)),m,priv);err!=nil{t.Fatal(err)}
 p,err:=core.VerifyPackage(bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys)
 if err!=nil{t.Fatal(err)}
 now:=time.Now()
 task:=core.Transaction{ID:"fixture",ServerID:42,PackageSHA256:p.PackageSHA256,Version:m.Version,ReleaseSequence:2,State:core.StateVerified,ExpiresAt:now.Add(time.Minute)}
 s,err:=upgradestate.Initialize(stateDir,42,1)
 if err!=nil{t.Fatal(err)}
 defer s.Close()
 if err:=s.ReserveVerified(task,p,"linux",runtime.GOARCH,"v0.30.00",now);err!=nil{t.Fatal(err)}
 i,err:=New(dir,s)
 if err!=nil{t.Fatal(err)}
 if _,err:=i.Install(task,bytes.NewReader(archive.Bytes()),int64(archive.Len()),nil,now);err==nil{t.Fatal("untrusted install")}
 health,err:=i.Install(task,bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys,now)
 if err!=nil||health.State!=core.StateHealthCheck{t.Fatal("install",err)}
 b,err:=os.ReadFile(target)
 if err!=nil||!bytes.Equal(b,body){t.Fatal("new binary missing",err)}
 if err:=s.Close();err!=nil{t.Fatal(err)}
 s,err=upgradestate.Open(stateDir,42)
 if err!=nil{t.Fatal(err)}
 defer s.Close()
 i,err=New(dir,s)
 if err!=nil{t.Fatal(err)}
 _,restored,err:=s.Snapshot()
 if err!=nil||restored==nil{t.Fatal("missing durable task",err)}
 back,err:=i.Restore(*restored,now.Add(time.Hour))
 if err!=nil||back.State!=core.StateRollingBack{t.Fatal("restore",err)}
 if _,err:=i.Restore(back,now.Add(time.Hour));err!=nil{t.Fatal("repeat restore",err)}
 b,err=os.ReadFile(target)
 if err!=nil||string(b)!="old worker fixture"{t.Fatal("old binary missing",err)}
 if _,err:=s.Advance(back,core.StateRolledBack,now.Add(time.Hour));err!=nil{t.Fatal(err)}
 high,_,err:=s.Snapshot()
 if err!=nil||high!=2{t.Fatal("sequence lost",err)}
}

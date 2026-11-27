//go:build linux

package upgradestate

import (
 "os"
 "path/filepath"
 "strings"
 "testing"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

func fixture(now time.Time,seq uint64)(core.Transaction,core.VerifiedPackage){
 m:=core.Manifest{FormatVersion:1,Component:"nezha-agent",Version:"v0.30.01",OS:"linux",Arch:"amd64",MinAgentVersion:"v0.30.00",ProtocolVersion:1,Filename:"nezha-agent",Size:123,SHA256:strings.Repeat("b",64),SigningKeyID:"test",ReleaseSequence:seq}
 p:=core.VerifiedPackage{Manifest:m,PackageSHA256:strings.Repeat("a",64)}
 t:=core.Transaction{ID:"fixture",ServerID:42,Version:m.Version,PackageSHA256:p.PackageSHA256,ReleaseSequence:seq,State:core.StateVerified,ExpiresAt:now.Add(time.Minute)}
 return t,p
}
func TestDurableRollback(t *testing.T){
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 if _,err:=Open(dir,42);err==nil{t.Fatal("missing state accepted")}
 s,err:=Initialize(dir,42,1)
 if err!=nil{t.Fatal(err)}
 defer s.Close()
 if other,err:=Open(dir,42);err==nil{other.Close();t.Fatal("second writer allowed")}
 now:=time.Now()
 task,p:=fixture(now,2)
 if err:=s.ReserveVerified(task,p,"linux","amd64","v0.30.00",now);err!=nil{t.Fatal(err)}
 if err:=s.ReserveVerified(task,p,"linux","amd64","v0.30.00",now);err==nil{t.Fatal("duplicate task allowed")}
 installing,err:=s.Advance(task,core.StateInstalling,now)
 if err!=nil{t.Fatal(err)}
 if _,err:=s.Advance(task,core.StateFailed,now);err==nil{t.Fatal("stale transition accepted")}
 if err:=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(dir,42)
 if err!=nil{t.Fatal(err)}
 defer s.Close()
 high,restored,err:=s.Snapshot()
 if err!=nil||high!=2||restored==nil||restored.State!=core.StateInstalling||!restored.SameIdentity(installing){t.Fatal("lost durable state",err)}
 action,err:=core.RecoveryDecision(*restored,now.Add(time.Hour))
 if err!=nil||action!=core.RecoveryRequireRollback{t.Fatal(action,err)}
 back,err:=s.Advance(*restored,core.StateRollingBack,now.Add(time.Hour))
 if err!=nil{t.Fatal(err)}
 if _,err:=s.Advance(back,core.StateRolledBack,now.Add(time.Hour));err!=nil{t.Fatal(err)}
 high,_,err=s.Snapshot()
 if err!=nil||high!=2{t.Fatal("rollback lowered high-water mark")}
 replay,p:=fixture(now,2);replay.ID="different"
 if err:=s.ReserveVerified(replay,p,"linux","amd64","v0.30.00",now);err==nil{t.Fatal("replayed sequence accepted")}
}
func TestFailClosedCorruption(t *testing.T){
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 s,err:=Initialize(dir,42,1)
 if err!=nil{t.Fatal(err)}
 s.Close()
 if other,err:=Open(dir,43);err==nil{other.Close();t.Fatal("accepted wrong server")}
 if other,err:=Initialize(dir,42,1);err==nil{other.Close();t.Fatal("reset accepted")}
 if err:=os.WriteFile(filepath.Join(dir,stateName),[]byte("broken"),0600);err!=nil{t.Fatal(err)}
 if other,err:=Open(dir,42);err==nil{other.Close();t.Fatal("corrupt state accepted")}
 if err:=os.Remove(filepath.Join(dir,stateName));err!=nil{t.Fatal(err)}
 if other,err:=Open(dir,42);err==nil{other.Close();t.Fatal("missing state silently reset")}
}

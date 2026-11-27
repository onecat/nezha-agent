//go:build linux

package upgradestate
import("os";"testing";"time";core "github.com/onecat/nezha-agent/pkg/agentupgrade")
func TestVersionAndReceiptDurable(t *testing.T){
 dir:=t.TempDir();if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 s,err:=InitializeVersion(dir,42,1,"v0.30.00")
 if err!=nil{t.Fatal(err)}
 defer s.Close()
 now:=time.Now();task,p:=fixture(now,2)
 if err:=s.ReserveVerified(task,p,"linux","amd64","v0.30.00",now);err!=nil{t.Fatal(err)}
 if err:=s.MarkReported(task);err==nil{t.Fatal("nonterminal acknowledgement")}
 for _,next:=range []core.State{core.StateInstalling,core.StateHealthCheck,core.StateSucceeded}{
  task,err=s.Advance(task,next,now);if err!=nil{t.Fatal(err)}
 }
 current,previous,reported,err:=s.VersionInfo()
 if err!=nil||current!="v0.30.01"||previous!="v0.30.00"||reported{t.Fatal("incorrect version metadata",err)}
 next,p2:=fixture(now,3)
 next.ID="next";next.Version="v0.30.02";p2.Manifest.Version=next.Version
 if err:=s.ReserveVerified(next,p2,"linux","amd64","v0.30.01",now);err==nil{t.Fatal("unreported result overwritten")}
 if err:=s.MarkReported(task);err!=nil{t.Fatal(err)}
 if err:=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(dir,42);if err!=nil{t.Fatal(err)}
 defer s.Close()
 current,previous,reported,err=s.VersionInfo()
 if err!=nil||current!="v0.30.01"||previous!="v0.30.00"||!reported{t.Fatal("metadata lost",err)}
 if err:=s.ReserveVerified(next,p2,"linux","amd64","v0.30.01",now);err!=nil{t.Fatal("reported task did not release reservation",err)}
}

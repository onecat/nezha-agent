package upgradestage

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "io"
 "os"
 "testing"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

func packageFixture(t *testing.T)([]byte,core.Transaction,map[string]ed25519.PublicKey){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 keys:=map[string]ed25519.PublicKey{"test":pub}
 body:=make([]byte,core.ChunkSize+17)
 if _,err:=rand.Read(body);err!=nil{t.Fatal(err)}
 var b bytes.Buffer
 m:=core.Manifest{Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:"linux",Arch:"amd64",SigningKeyID:"test",ReleaseSequence:2}
 if _,err:=core.BuildPackage(&b,bytes.NewReader(body),int64(len(body)),m,priv);err!=nil{t.Fatal(err)}
 p,err:=core.VerifyPackage(bytes.NewReader(b.Bytes()),int64(b.Len()),keys)
 if err!=nil{t.Fatal(err)}
 return b.Bytes(),core.Transaction{ID:"fixture",ServerID:42,PackageSHA256:p.PackageSHA256,Version:m.Version,ReleaseSequence:2,State:core.StateTransferring,ExpiresAt:time.Now().Add(time.Minute)},keys
}
func transfer(t *testing.T,s *Stage,b []byte,task core.Transaction){
 t.Helper()
 sender,err:=core.NewSender(task,bytes.NewReader(b),int64(len(b)))
 if err!=nil{t.Fatal(err)}
 var offset int64
 for{
  c,done,err:=sender.ChunkAt(offset)
  if err!=nil{t.Fatal(err)}
  if done{break}
  if err:=s.WriteChunk(c,time.Now());err!=nil{t.Fatal(err)}
  offset+=int64(len(c.Data))
 }
}
func TestSealAndCleanup(t *testing.T){
 b,task,keys:=packageFixture(t)
 dir:=t.TempDir()
 if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
 s,err:=New(dir,task,int64(len(b)),time.Now())
 if err!=nil{t.Fatal(err)}
 defer s.Close()
 if _,err:=s.ReadAt(make([]byte,1),0);err==nil{t.Fatal("unverified read")}
 transfer(t,s,b,task)
 p,err:=s.Seal(keys,"linux","amd64","v0.30.00",1,time.Now())
 if err!=nil||p.PackageSHA256!=task.PackageSHA256{t.Fatal("seal failed",err)}
 got,err:=io.ReadAll(io.NewSectionReader(s,0,int64(len(b))))
 if err!=nil||!bytes.Equal(got,b){t.Fatal("verified bytes changed",err)}
 if err:=s.Close();err!=nil{t.Fatal(err)}
 entries,err:=os.ReadDir(dir)
 if err!=nil||len(entries)!=0{t.Fatal("stage not cleaned",err)}
}
func TestRejectExpiredWrongIdentityAndReplay(t *testing.T){
 b,task,keys:=packageFixture(t)
 for _,mode:=range []string{"wrong-id","expired","replay","untrusted"}{
  t.Run(mode,func(t *testing.T){
   dir:=t.TempDir()
   if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
   s,err:=New(dir,task,int64(len(b)),time.Now())
   if err!=nil{t.Fatal(err)}
   defer s.Close()
   if mode=="wrong-id"||mode=="expired"{
    c:=core.Chunk{TaskID:task.ID,ServerID:task.ServerID,PackageSHA256:task.PackageSHA256,Data:b[:1]}
    now:=time.Now()
    if mode=="wrong-id"{c.ServerID++}else{now=task.ExpiresAt}
    if err:=s.WriteChunk(c,now);err==nil{t.Fatal("invalid chunk accepted")}
   }else{
    transfer(t,s,b,task)
    high:=uint64(1);trust:=keys
    if mode=="replay"{high=2}else{trust=nil}
    if _,err:=s.Seal(trust,"linux","amd64","v0.30.00",high,time.Now());err==nil{t.Fatal("invalid package accepted")}
   }
   entries,err:=os.ReadDir(dir)
   if err!=nil||len(entries)!=0{t.Fatal("invalid stage left on disk",err)}
  })
 }
}

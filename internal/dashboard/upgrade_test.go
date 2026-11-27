package dashboard

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "io"
 "os"
 "sync/atomic"
 "testing"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 wire "github.com/onecat/nezha-agent/pkg/upgradewire"
 "google.golang.org/grpc"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
 "google.golang.org/protobuf/types/known/wrapperspb"
)

type upgradeFixture struct{
 task core.Transaction
 archive []byte
 truncated bool
 receipts atomic.Int64
}
func(f *upgradeFixture) Download(req *wrapperspb.BytesValue,stream grpc.ServerStream)error{
 if err:=auth(stream.Context());err!=nil{return err}
 if len(req.Value)!=0{return status.Error(codes.InvalidArgument,"invalid request")}
 h,err:=wire.EncodeHeader(wire.Header{Task:f.task,Size:int64(len(f.archive))})
 if err!=nil{return err}
 if err:=stream.SendMsg(wrapperspb.Bytes(h));err!=nil{return err}
 if f.truncated{return nil}
 s,err:=core.NewSender(f.task,bytes.NewReader(f.archive),int64(len(f.archive)))
 if err!=nil{return err}
 for offset:=int64(0);;{
  c,done,err:=s.ChunkAt(offset)
  if err!=nil{return err}
  if done{return nil}
  b,err:=wire.EncodeChunk(c)
  if err!=nil{return err}
  if err:=stream.SendMsg(wrapperspb.Bytes(b));err!=nil{return err}
  offset+=int64(len(c.Data))
 }
}
func(f *upgradeFixture) Verify(ctx context.Context,req *wrapperspb.BytesValue)(*wrapperspb.BytesValue,error){
 if err:=auth(ctx);err!=nil{return nil,err}
 t,err:=core.DecodeSnapshot(req.Value)
 if err!=nil||t.State!=core.StateVerified||!t.SameIdentity(f.task)||!t.ExpiresAt.Equal(f.task.ExpiresAt){return nil,status.Error(codes.InvalidArgument,"bad receipt")}
 f.receipts.Add(1)
 return wrapperspb.Bytes([]byte("verified")),nil
}
func TestTLSManagedDownload(t *testing.T){
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 keys:=map[string]ed25519.PublicKey{"test":pub}
 body:=make([]byte,core.ChunkSize+71)
 if _,err:=rand.Read(body);err!=nil{t.Fatal(err)}
 var archive bytes.Buffer
 m:=core.Manifest{Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:"linux",Arch:"amd64",SigningKeyID:"test",ReleaseSequence:2}
 if _,err:=core.BuildPackage(&archive,bytes.NewReader(body),int64(len(body)),m,priv);err!=nil{t.Fatal(err)}
 p,err:=core.VerifyPackage(bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys)
 if err!=nil{t.Fatal(err)}
 for _,mode:=range []string{"success","wrong-server","untrusted-key","truncated","replay","wrong-secret"}{
  t.Run(mode,func(t *testing.T){
   f:=&upgradeFixture{task:core.Transaction{ID:"fixture",ServerID:42,PackageSHA256:p.PackageSHA256,Version:m.Version,ReleaseSequence:2,State:core.StateTransferring,ExpiresAt:time.Now().Add(time.Minute)},archive:archive.Bytes(),truncated:mode=="truncated"}
   address,roots:=startServer(t,true,func(g *grpc.Server){wire.Register(g,f)})
   secret:="test-secret"
   if mode=="wrong-secret"{secret="wrong"}
   c,err:=New(Config{Address:address,Secret:secret,RootCAs:roots})
   if err!=nil{t.Fatal(err)}
   defer c.Close()
   ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
   defer cancel()
   dir:=t.TempDir()
   if err:=os.Chmod(dir,0700);err!=nil{t.Fatal(err)}
   high,server:=uint64(1),uint64(42)
   trust:=keys
   switch mode{
   case "wrong-server":server=43
   case "untrusted-key":trust=map[string]ed25519.PublicKey{"other":pub}
   case "replay":high=2
   }
   d,err:=c.DownloadUpgrade(ctx,dir,server,"v0.30.00","linux","amd64",high,trust)
   if mode!="success"{
    if err==nil{d.Close();t.Fatal("invalid download accepted")}
   }else{
    if err!=nil{t.Fatal(err)}
    defer d.Close()
    if d.Package()!=p||d.Task().State!=core.StateVerified{t.Fatal("download mismatch")}
    b,err:=io.ReadAll(io.NewSectionReader(d,0,d.Size()))
    if err!=nil||!bytes.Equal(b,archive.Bytes()){t.Fatal("archive mismatch",err)}
    if err:=c.AcknowledgeVerified(ctx,d);err!=nil{t.Fatal(err)}
    if f.receipts.Load()!=1{t.Fatal("missing verified receipt")}
    if err:=d.Close();err!=nil{t.Fatal(err)}
    if err:=c.AcknowledgeVerified(ctx,d);err==nil{t.Fatal("closed stage acknowledged")}
   }
   entries,err:=os.ReadDir(dir)
   if err!=nil||len(entries)!=0{t.Fatal("staging leak",err)}
  })
 }
}

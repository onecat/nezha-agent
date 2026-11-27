package agentupgrade

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "testing"
 "time"
)

func TestManagedTransferAndVerification(t *testing.T) {
 pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil {t.Fatal(err)}
 keys:=map[string]ed25519.PublicKey{"test":pub}
 body:=make([]byte,ChunkSize*2+100)
 if _,err:=rand.Read(body);err!=nil {t.Fatal(err)}
 var archive bytes.Buffer
 manifest:=Manifest{Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:"linux",Arch:"amd64",SigningKeyID:"test",ReleaseSequence:2}
 if _,err:=BuildPackage(&archive,bytes.NewReader(body),int64(len(body)),manifest,priv);err!=nil{t.Fatal(err)}
 v,err:=VerifyPackage(bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys)
 if err!=nil{t.Fatal(err)}
 now:=time.Now()
 task:=Transaction{ID:"test-task",ServerID:1,PackageSHA256:v.PackageSHA256,Version:v.Manifest.Version,ReleaseSequence:v.Manifest.ReleaseSequence,State:StatePending,ExpiresAt:now.Add(time.Minute)}
 policy:=AuthorizationPolicy{Enabled:true,OperatorCanUpgrade:true,ServerAllowsUpgrade:true,AgentSupportsUpgrade:true,AgentVersion:"v0.30.00",AgentOS:"linux",AgentArch:"amd64",Now:now}
 if err:=policy.AuthorizeUpgrade(task,v,1);err!=nil{t.Fatal(err)}
 task,err=task.Transition(StateTransferring,now)
 if err!=nil{t.Fatal(err)}
 sender,err:=NewSender(task,bytes.NewReader(archive.Bytes()),int64(archive.Len()))
 if err!=nil{t.Fatal(err)}
 var staged bytes.Buffer
 receiver,err:=NewReceiver(task.ID,task.ServerID,task.PackageSHA256,int64(archive.Len()),&staged)
 if err!=nil{t.Fatal(err)}
 var offset int64
 chunks:=0
 for {
  c,done,err:=sender.ChunkAt(offset)
  if err!=nil{t.Fatal(err)}
  if done{break}
  if err:=receiver.WriteChunk(c);err!=nil{t.Fatal(err)}
  offset+=int64(len(c.Data))
  chunks++
 }
 if chunks<3{t.Fatal("expected multi-chunk fixture")}
 if err:=receiver.Finish();err!=nil{t.Fatal(err)}
 got,err:=VerifyPackage(bytes.NewReader(staged.Bytes()),int64(staged.Len()),keys)
 if err!=nil || got!=v{t.Fatalf("verification mismatch: %v",err)}
 if err:=got.Manifest.CheckUpgrade("linux","amd64","v0.30.00",1);err!=nil{t.Fatal(err)}
 if err:=got.Manifest.CheckUpgrade("linux","amd64","v0.30.00",2);err==nil{t.Fatal("accepted replay sequence")}
 task,err=task.Transition(StateVerified,now)
 if err!=nil{t.Fatal(err)}
 b,err:=EncodeSnapshot(task)
 if err!=nil{t.Fatal(err)}
 restored,err:=DecodeSnapshot(b)
 if err!=nil||!restored.SameIdentity(task)||restored.State!=StateVerified{t.Fatal("snapshot mismatch",err)}
}

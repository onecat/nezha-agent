//go:build linux

package main

import(
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "os"
 "path/filepath"
 "testing"
 "time"
 "github.com/onecat/nezha-agent/internal/upgradestate"
 "github.com/onecat/nezha-agent/internal/upgradeinstall"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)
func TestDirectCandidateAndRecovery(t *testing.T){
 for _,success:=range []bool{true,false}{
 t.Run(map[bool]string{true:"healthy",false:"failed-exec"}[success],func(t *testing.T){
  root:=t.TempDir();if err:=os.Chmod(root,0700);err!=nil{t.Fatal(err)}
  _,state,_:=directPaths(root);if err:=os.Mkdir(state,0700);err!=nil{t.Fatal(err)}
  l,err:=upgradestate.InitializeVersion(state,42,1,"v0.30.03");if err!=nil{t.Fatal(err)};defer l.Close()
  old:=[]byte("old executable");candidate:=[]byte("new executable")
  if err:=os.WriteFile(filepath.Join(root,"nezha-agent"),old,0700);err!=nil{t.Fatal(err)}
  if err:=refreshRecovery(root);err!=nil{t.Fatal(err)}
  pub,key,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
  keys:=map[string]ed25519.PublicKey{"test":pub}
  var archive bytes.Buffer
  m:=core.Manifest{Version:"v0.30.04",MinAgentVersion:"v0.30.03",OS:"linux",Arch:"amd64",SigningKeyID:"test",ReleaseSequence:2}
  if _,err:=core.BuildPackage(&archive,bytes.NewReader(candidate),int64(len(candidate)),m,key);err!=nil{t.Fatal(err)}
  p,err:=core.VerifyPackage(bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys);if err!=nil{t.Fatal(err)}
  now:=time.Now()
  tx:=core.Transaction{ID:"direct-test",ServerID:42,PackageSHA256:p.PackageSHA256,Version:m.Version,ReleaseSequence:2,State:core.StateVerified,ExpiresAt:now.Add(time.Minute)}
  if err:=l.ReserveVerified(tx,p,"linux","amd64","v0.30.03",now);err!=nil{t.Fatal(err)}
  installer,err:=upgradeinstall.New(root,l);if err!=nil{t.Fatal(err)}
  if _,err:=installer.Install(tx,bytes.NewReader(archive.Bytes()),int64(archive.Len()),keys,now);err!=nil{t.Fatal(err)}
  if err:=prepareLedger(root,l,time.Now());err!=nil{t.Fatal(err)}
  if success{
   if err:=checkStartupVersion(l,"v0.30.03");err==nil{t.Fatal("wrong candidate version accepted")}
   if err:=completeHealth(l,"v0.30.04",time.Now());err!=nil{t.Fatal(err)}
  }else{
   if err:=prepareLedger(root,l,time.Now());err!=nil{t.Fatal(err)}
   b,err:=os.ReadFile(filepath.Join(root,"nezha-agent"));if err!=nil||!bytes.Equal(b,old){t.Fatal("old executable not restored",err)}
   if err:=completeHealth(l,"v0.30.03",time.Now());err!=nil{t.Fatal(err)}
  }
  high,s,err:=l.Snapshot();if err!=nil||high!=2{t.Fatal(high,err)}
  want:=core.StateRolledBack;if success{want=core.StateSucceeded}
  if s.State!=want{t.Fatal(s.State,want)}
 })
 }
}

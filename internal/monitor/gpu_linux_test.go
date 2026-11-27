//go:build linux

package monitor

import (
 "os"
 "path/filepath"
 "testing"
)

func TestGPUReadings(t *testing.T){
 root:=t.TempDir()
 dir:=filepath.Join(root,"card0","device")
 if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
 busy:=filepath.Join(dir,"gpu_busy_percent")
 if err:=os.WriteFile(busy,[]byte("37\n"),0600);err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(dir,"vendor"),[]byte("0x1002\n"),0600);err!=nil{t.Fatal(err)}
 if got:=gpuUsageAt(root);got!=37{t.Fatalf("usage=%v",got)}
 names:=gpuNamesAt(root)
 if len(names)!=1||names[0]!="card0 (AMD)"{t.Fatalf("names=%v",names)}
 for _,invalid:=range []string{"-1","101","NaN","Inf","oops"}{
  if err:=os.WriteFile(busy,[]byte(invalid),0600);err!=nil{t.Fatal(err)}
  if got:=gpuUsageAt(root);got!=0{t.Fatalf("%q usage=%v",invalid,got)}
  if len(gpuNamesAt(root))!=0{t.Fatalf("invalid GPU should be hidden: %q",invalid)}
 }
 if err:=os.Remove(busy);err!=nil{t.Fatal(err)}
 if got:=gpuUsageAt(root);got!=0{t.Fatal(got)}
}
func TestGPUMultiCard(t *testing.T){
 root:=t.TempDir()
 for name,value:=range map[string]string{"card0":"20","card1":"60"}{
  dir:=filepath.Join(root,name,"device")
  if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)}
  if err:=os.WriteFile(filepath.Join(dir,"gpu_busy_percent"),[]byte(value),0600);err!=nil{t.Fatal(err)}
 }
 if got:=gpuUsageAt(root);got!=40{t.Fatalf("average=%v",got)}
}

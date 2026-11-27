package monitor
import("testing";"time";"os";"path/filepath";"reflect")

func TestSelectPVE(t *testing.T){
 infos:=map[string]nicInfo{
  "eno1":{physical:true,master:"vmbr0"},"eno2":{physical:true,master:"bond0"},
  "eno3":{physical:true,master:"bond0"},"bond0":{bond:true,master:"vmbr1"},
  "vmbr0":{bridge:true},"vmbr1":{bridge:true},"tap100i0":{},
  "fwbr100i0":{bridge:true},"fwln100i0":{},"fwpr100p0":{},
  "veth100i0":{},"lo":{excluded:true},"docker0":{bridge:true},
 }
 if got:=selectNICs(infos,nil);!reflect.DeepEqual(got,map[string]bool{"eno1":true,"bond0":true}){t.Fatal(got)}
 if got:=selectNICs(infos,[]string{"vmbr0","missing"});!reflect.DeepEqual(got,map[string]bool{"vmbr0":true}){t.Fatal(got)}
}
func TestGuestAndContainer(t *testing.T){
 for _,physical:=range []bool{false,true}{
  infos:=map[string]nicInfo{"eth0":{physical:physical},"lo":{excluded:true},"docker0":{bridge:true},"veth123":{},"tap100":{}}
  if got:=selectNICs(infos,nil);!reflect.DeepEqual(got,map[string]bool{"eth0":true}){t.Fatal(got)}
 }
}
func TestLinuxTopology(t *testing.T){
 root:=t.TempDir()
 for _,p:=range []string{"eno1/device","eno2/device","bond0/bonding","vmbr0/bridge","tap100"}{if err:=os.MkdirAll(filepath.Join(root,p),0700);err!=nil{t.Fatal(err)}}
 if err:=os.Symlink("../bond0",filepath.Join(root,"eno2","master"));err!=nil{t.Fatal(err)}
 if err:=os.Symlink("../vmbr0",filepath.Join(root,"eno1","master"));err!=nil{t.Fatal(err)}
 if err:=os.WriteFile(filepath.Join(root,"tap100","tun_flags"),[]byte("0x2"),0600);err!=nil{t.Fatal(err)}
 infos:=map[string]nicInfo{}
 for _,name:=range []string{"eno1","eno2","bond0","vmbr0","tap100"}{infos[name]=linuxNIC(root,name)}
 if got:=selectNICs(infos,nil);!reflect.DeepEqual(got,map[string]bool{"eno1":true,"bond0":true}){t.Fatal(got)}
}
func TestAsymmetricTrafficAndInterfaceChanges(t *testing.T){
 n:=new(networkTracker);at:=time.Now()
 check:=func(sec int,s map[string]nicCounter,want [4]uint64){
  a,b,c,d:=n.update(s,at.Add(time.Duration(sec)*time.Second))
  if got:=[4]uint64{a,b,c,d};got!=want{t.Fatalf("at %d got %v want %v",sec,got,want)}
 }
 check(0,map[string]nicCounter{"eno1":{1000,500,1}},[4]uint64{1000,500,0,0})
 check(1,map[string]nicCounter{"eno1":{1100,505,1}},[4]uint64{1100,505,100,5})
 check(2,map[string]nicCounter{"eno1":{1102,705,1},"eno2":{999999,999999,2}},[4]uint64{1102,705,2,200})
 check(3,map[string]nicCounter{"eno2":{1000009,1000000,2}},[4]uint64{1112,706,10,1})
 check(4,map[string]nicCounter{"eno2":{3,1000004,2}},[4]uint64{1112,710,0,4})
 check(5,map[string]nicCounter{"eno2":{5000000,5000000,3}},[4]uint64{1112,710,0,0})
 check(6,map[string]nicCounter{},[4]uint64{1112,710,0,0})
 check(7,map[string]nicCounter{"eno2":{6000000,6000000,3}},[4]uint64{1112,710,0,0})
 check(9,map[string]nicCounter{"eno2":{6000200,6000002,3}},[4]uint64{1312,712,100,1})
}
func TestForwardingLegDoesNotMirrorWAN(t *testing.T){
 infos:=map[string]nicInfo{"eno1":{physical:true},"vmbr0":{bridge:true},"tap100i0":{},"fwpr100p0":{}}
 n:=new(networkTracker);now:=time.Now()
 sample:=func(rx,tx uint64)map[string]nicCounter{
  raw:=map[string]nicCounter{"eno1":{rx,tx,1},"vmbr0":{rx,tx,2},"tap100i0":{tx,rx,3},"fwpr100p0":{tx,rx,4}}
  chosen:=selectNICs(infos,nil);for name:=range raw{if !chosen[name]{delete(raw,name)}};return raw
 }
 n.update(sample(1000,200),now)
 _,_,rx,tx:=n.update(sample(100001000,1200),now.Add(time.Second))
 if rx!=100000000||tx!=1000{t.Fatal(rx,tx)}
}

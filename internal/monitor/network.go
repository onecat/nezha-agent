package monitor

import (
 "context"
 "errors"
 "math"
 "net"
 "os"
 "path/filepath"
 "runtime"
 "strconv"
 "strings"
 "time"

 netstat "github.com/shirou/gopsutil/v4/net"
)

type nicCounter struct{
 in,out uint64
 index int
}
type nicInfo struct{
 physical,bond,bridge,excluded bool
 master string
}
func internalName(name string)bool{
 n:=strings.ToLower(name)
 if n=="lo"||n=="docker0"||n=="virbr0"||n=="dummy0"{return true}
 for _,prefix:=range []string{"tap","tun","veth","fwbr","fwln","fwpr","docker","virbr","br-","cni","flannel","cali","lxc","vnet","dummy","ifb","vlan","macvlan","ipvlan","wg","tailscale","zt","vxlan","geneve","sit","gre","gretap","ip6tnl"}{
  if strings.HasPrefix(n,prefix){return true}
 }
 return false
}
func exists(p string)bool{_,err:=os.Stat(p);return err==nil}
func linuxNIC(root,name string)nicInfo{
 p:=filepath.Join(root,name)
 x:=nicInfo{physical:exists(filepath.Join(p,"device")),bond:exists(filepath.Join(p,"bonding")),bridge:exists(filepath.Join(p,"bridge"))}
 if target,err:=os.Readlink(filepath.Join(p,"master"));err==nil{x.master=filepath.Base(target)}
 x.excluded=name=="lo"||exists(filepath.Join(p,"tun_flags"))
 return x
}
// Auto mode counts the wire-facing physical devices and bond masters, not
// bridge/TAP forwarding legs. Bridge slaves remain eligible if physical;
// bond slaves are excluded. A VPS/container with no visible physical device
// can use an ordinary non-bridge virtual NIC such as eth0.
func selectNICs(infos map[string]nicInfo,explicit []string)map[string]bool{
 chosen:=map[string]bool{}
 if len(explicit)>0{
  for _,name:=range explicit{if _,ok:=infos[name];ok{chosen[name]=true}}
  return chosen
 }
 for name,x:=range infos{
  if x.excluded||name=="lo"||x.bridge||infos[x.master].bond{continue}
  if x.physical||x.bond{chosen[name]=true}
 }
 if len(chosen)>0{return chosen}
 for name,x:=range infos{
  if x.excluded||x.bridge||internalName(name)||infos[x.master].bond{continue}
  chosen[name]=true
 }
 return chosen
}
func networkSample(ctx context.Context,explicit []string)(map[string]nicCounter,error){
 rows,err:=netstat.IOCountersWithContext(ctx,true)
 if err!=nil{return nil,err}
 if len(rows)==0{return nil,errors.New("missing network counters")}
 infos:=map[string]nicInfo{}
 counters:=map[string]nicCounter{}
 for _,row:=range rows{
  if row.Name==""||filepath.Base(row.Name)!=row.Name||row.Name=="."||row.Name==".."{continue}
  x:=nicInfo{excluded:row.Name=="lo"}
  index:=0
  if runtime.GOOS=="linux"{
   x=linuxNIC("/sys/class/net",row.Name)
   if b,err:=os.ReadFile(filepath.Join("/sys/class/net",row.Name,"ifindex"));err==nil{index,_=strconv.Atoi(strings.TrimSpace(string(b)))}
  }else if nic,err:=net.InterfaceByName(row.Name);err==nil{
   x.excluded=nic.Flags&net.FlagLoopback!=0;index=nic.Index
  }
  // An interface disappearing between the counter and topology reads is not
  // a stable sample. Do not treat its old lifetime bytes as a new delta.
  if runtime.GOOS=="linux"&&index<=0{continue}
  infos[row.Name]=x
  counters[row.Name]=nicCounter{in:row.BytesRecv,out:row.BytesSent,index:index}
 }
 selected:=selectNICs(infos,explicit)
 for name:=range counters{if !selected[name]{delete(counters,name)}}
 // A temporarily missing explicitly configured NIC contributes zero speed;
 // do not silently fall back to unrelated devices or stop all other metrics.
 return counters,nil
}
type networkTracker struct{
 previous map[string]nicCounter
 at time.Time
 in,out uint64
}
func add(a,b uint64)uint64{if math.MaxUint64-a<b{return math.MaxUint64};return a+b}
func delta(old,new uint64)uint64{if new<old{return 0};return new-old}
func(n *networkTracker) update(sample map[string]nicCounter,now time.Time)(in,out,inSpeed,outSpeed uint64){
 if n.at.IsZero(){
  for _,v:=range sample{n.in=add(n.in,v.in);n.out=add(n.out,v.out)}
 }else if seconds:=now.Sub(n.at).Seconds();seconds>0{
  var di,do uint64
  for name,v:=range sample{
   old,ok:=n.previous[name]
   if !ok||old.index!=v.index{continue}
   di=add(di,delta(old.in,v.in));do=add(do,delta(old.out,v.out))
  }
  n.in=add(n.in,di);n.out=add(n.out,do)
  inSpeed=speed(0,di,seconds);outSpeed=speed(0,do,seconds)
 }
 n.previous=sample;n.at=now
 return n.in,n.out,inSpeed,outSpeed
}

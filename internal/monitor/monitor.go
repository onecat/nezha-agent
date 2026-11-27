// Package monitor collects local machine metrics without public IP discovery.
package monitor

import (
 "context"
 "errors"
 "math"
 "os"
 "path/filepath"
 "runtime"
 "strings"
 "sync"
 "time"

 "github.com/onecat/nezha-agent/model"
 "github.com/shirou/gopsutil/v4/cpu"
 "github.com/shirou/gopsutil/v4/disk"
 "github.com/shirou/gopsutil/v4/host"
 "github.com/shirou/gopsutil/v4/mem"
 netstat "github.com/shirou/gopsutil/v4/net"
)

type Collector struct {
 mu sync.Mutex
 last counters
}
type counters struct {
 in,out uint64
 at time.Time
}

func rootDisk() string {
 if runtime.GOOS=="windows" {
  drive:=os.Getenv("SystemDrive")
  if len(drive)==2 && drive[1]==':' && strings.Contains("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",drive[:1]) {
   return drive+string(filepath.Separator)
  }
  return `C:\`
 }
 return "/"
}

func (c *Collector) Host(ctx context.Context,version string)(*model.Host,error){
 h,err:=host.InfoWithContext(ctx)
 if err!=nil { return nil,err }
 m,err:=mem.VirtualMemoryWithContext(ctx)
 if err!=nil { return nil,err }
 s,err:=mem.SwapMemoryWithContext(ctx)
 if err!=nil { return nil,err }
 d,err:=disk.UsageWithContext(ctx,rootDisk())
 if err!=nil { return nil,err }
 cpus,err:=cpu.InfoWithContext(ctx)
 if err!=nil { return nil,err }
 names:=make([]string,0)
 seen:=make(map[string]bool)
 for _,v:=range cpus {
  name:=strings.TrimSpace(v.ModelName)
  if name!="" && !seen[name] { seen[name]=true;names=append(names,name) }
 }
 return &model.Host{Platform:h.Platform,PlatformVersion:h.PlatformVersion,
  CPU:names,MemTotal:m.Total,SwapTotal:s.Total,DiskTotal:d.Total,
  Arch:runtime.GOARCH,Virtualization:h.VirtualizationSystem,BootTime:h.BootTime,
  Version:version},nil
}

func speed(old,current uint64,seconds float64)uint64{
 if current<old || seconds<=0 { return 0 }
 n:=float64(current-old)/seconds
 if n>=float64(math.MaxUint64) { return math.MaxUint64 }
 return uint64(n)
}

func (c *Collector) State(ctx context.Context)(*model.HostState,error){
 c.mu.Lock()
 defer c.mu.Unlock()
 p,err:=cpu.PercentWithContext(ctx,200*time.Millisecond,false)
 if err!=nil { return nil,err }
 if len(p)!=1 || math.IsNaN(p[0]) || math.IsInf(p[0],0) || p[0]<0 || p[0]>100 {
  return nil,errors.New("invalid CPU measurement")
 }
 m,err:=mem.VirtualMemoryWithContext(ctx)
 if err!=nil { return nil,err }
 s,err:=mem.SwapMemoryWithContext(ctx)
 if err!=nil { return nil,err }
 d,err:=disk.UsageWithContext(ctx,rootDisk())
 if err!=nil { return nil,err }
 up,err:=host.UptimeWithContext(ctx)
 if err!=nil { return nil,err }
 io,err:=netstat.IOCountersWithContext(ctx,false)
 if err!=nil { return nil,err }
 if len(io)!=1 { return nil,errors.New("missing network counters") }
 now:=time.Now()
 result:=&model.HostState{CPU:p[0],MemUsed:m.Used,SwapUsed:s.Used,DiskUsed:d.Used,
  Uptime:up,NetInTransfer:io[0].BytesRecv,NetOutTransfer:io[0].BytesSent}
 if !c.last.at.IsZero() {
  seconds:=now.Sub(c.last.at).Seconds()
  result.NetInSpeed=speed(c.last.in,result.NetInTransfer,seconds)
  result.NetOutSpeed=speed(c.last.out,result.NetOutTransfer,seconds)
 }
 c.last=counters{in:result.NetInTransfer,out:result.NetOutTransfer,at:now}
 return result,nil
}

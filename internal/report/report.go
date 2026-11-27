// Package report implements the bounded, cancellation-aware reporting loop.
package report

import (
 "context"
 "errors"
 "net/netip"
 "strings"
 "time"

 "github.com/onecat/nezha-agent/model"
 pb "github.com/onecat/nezha-agent/proto"
)

type Collector interface {
 Host(context.Context,string)(*model.Host,error)
 State(context.Context)(*model.HostState,error)
}
type Dashboard interface {
 ReportHost(context.Context,*pb.Host)error
 ReportState(context.Context,*pb.State)error
}

type IPSource interface {
 Lookup(context.Context)(string,error)
}
type GeoLookup interface {
 LookupGeoIP(context.Context,string)error
}
type Loop struct {
 // IPSource is optional. The executable must explicitly wire DefaultConfig
 // or operator settings. No query occurs for a nil or disabled source.
 IPSource IPSource
 GeoLookup GeoLookup
 PreferIPv6Geo bool
 OnIPFailure func()

 Collector Collector
 Dashboard Dashboard
 Version string
 Interval time.Duration
 // OnFailure is an optional notification without raw RPC errors or secrets.
 OnFailure func()
}

func wait(ctx context.Context,d time.Duration)error {
 t:=time.NewTimer(d)
 defer t.Stop()
 select {
 case <-ctx.Done():return ctx.Err()
 case <-t.C:return nil
 }
}

func (l Loop) Run(ctx context.Context)error {
 if l.Collector==nil || l.Dashboard==nil || l.Version=="" || l.Interval<time.Second || l.Interval>time.Minute {
  return errors.New("invalid report loop settings")
 }
 var nextHost time.Time
 var ipCache string
 retry:=time.Second
 for {
  if err:=ctx.Err();err!=nil { return err }
  err:=l.onceWithIP(ctx,&nextHost,&ipCache)
  if err!=nil {
   nextHost=time.Time{}
   if ctx.Err()!=nil { return ctx.Err() }
   if l.OnFailure!=nil { l.OnFailure() }
   if err:=wait(ctx,retry);err!=nil { return err }
   retry*=2
   if retry>30*time.Second { retry=30*time.Second }
   continue
  }
  retry=time.Second
  if err:=wait(ctx,l.Interval);err!=nil { return err }
 }
}

func (l Loop) once(ctx context.Context,nextHost *time.Time)error {
 var cache string
 return l.onceWithIP(ctx,nextHost,&cache)
}

func (l Loop) onceWithIP(ctx context.Context,nextHost *time.Time,ipCache *string)error {
 if !time.Now().Before(*nextHost) {
  sample,cancel:=context.WithTimeout(ctx,30*time.Second)
  defer cancel()

  h,err:=l.Collector.Host(sample,l.Version)
  if err!=nil { return err }
  if h==nil { return errors.New("missing host sample") }
  if l.IPSource!=nil {
   ip,err:=l.IPSource.Lookup(sample)
   if err==nil { *ipCache=ip } else if l.OnIPFailure!=nil { l.OnIPFailure() }
   h.IP=*ipCache
  }
  if err:=l.Dashboard.ReportHost(sample,h.PB());err!=nil { return err }
  if l.GeoLookup!=nil && h.IP!="" {
   ip:=geoAddress(h.IP,l.PreferIPv6Geo)
   if ip!="" {
    if err:=l.GeoLookup.LookupGeoIP(sample,ip);err!=nil && l.OnIPFailure!=nil { l.OnIPFailure() }
   }
  }
  *nextHost=time.Now().Add(5*time.Minute)
 }
 sample,cancel:=context.WithTimeout(ctx,15*time.Second)
 defer cancel()
 s,err:=l.Collector.State(sample)
 if err!=nil { return err }
 if s==nil { return errors.New("missing state sample") }
 return l.Dashboard.ReportState(sample,s.PB())
}

func geoAddress(value string,preferV6 bool)string {
 var v4,v6 string
 for _,part:=range strings.Split(value,"/") {
  a,err:=netip.ParseAddr(part)
  if err!=nil || a.Zone()!="" || a.Is4In6() { continue }
  if a.Is4(){v4=a.String()}else if a.Is6(){v6=a.String()}
 }
 if preferV6 && v6!="" {return v6}
 if v4!="" {return v4}
 return v6
}

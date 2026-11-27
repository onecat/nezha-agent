// Package report implements the bounded, cancellation-aware reporting loop.
package report

import (
 "context"
 "errors"
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

type Loop struct {
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
 retry:=time.Second
 for {
  if err:=ctx.Err();err!=nil { return err }
  err:=l.once(ctx,&nextHost)
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
 sample,cancel:=context.WithTimeout(ctx,15*time.Second)
 defer cancel()
 if !time.Now().Before(*nextHost) {
  h,err:=l.Collector.Host(sample,l.Version)
  if err!=nil { return err }
  if h==nil { return errors.New("missing host sample") }
  if err:=l.Dashboard.ReportHost(sample,h.PB());err!=nil { return err }
  *nextHost=time.Now().Add(5*time.Minute)
 }
 s,err:=l.Collector.State(sample)
 if err!=nil { return err }
 if s==nil { return errors.New("missing state sample") }
 return l.Dashboard.ReportState(sample,s.PB())
}

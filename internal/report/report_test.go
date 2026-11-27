package report

import (
 "context"
 "errors"
 "reflect"
 "testing"
 "time"

 "github.com/onecat/nezha-agent/model"
 pb "github.com/onecat/nezha-agent/proto"
)
type fixture struct {
 events []string
 fail bool
 stop context.CancelFunc
}
func(f *fixture) Host(context.Context,string)(*model.Host,error){return &model.Host{Version:"v0.30.00"},nil}
func(f *fixture) State(context.Context)(*model.HostState,error){return &model.HostState{MemUsed:7},nil}
func(f *fixture) ReportHost(_ context.Context,h *pb.Host)error{
 f.events=append(f.events,"host")
 if h.GetVersion()!="v0.30.00" {return errors.New("bad version")}
 return nil
}
func(f *fixture) ReportState(_ context.Context,s *pb.State)error{
 f.events=append(f.events,"state")
 if s.GetMemUsed()!=7 { return errors.New("bad metric") }
 if f.fail { f.fail=false;return errors.New("test disconnect") }
 if f.stop!=nil { f.stop() }
 return nil
}
func TestRetryReportsHostFirst(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
 defer cancel()
 f:=&fixture{fail:true,stop:cancel}
 l:=Loop{Collector:f,Dashboard:f,Version:"v0.30.00",Interval:time.Second}
 if err:=l.Run(ctx);!errors.Is(err,context.Canceled){t.Fatal(err)}
 if !reflect.DeepEqual(f.events,[]string{"host","state","host","state"}){t.Fatal(f.events)}
}
func TestHostRefreshInterval(t *testing.T){
 f:=new(fixture)
 l:=Loop{Collector:f,Dashboard:f,Version:"v0.30.00",Interval:time.Second}
 var next time.Time
 if err:=l.once(context.Background(),&next);err!=nil {t.Fatal(err)}
 if err:=l.once(context.Background(),&next);err!=nil {t.Fatal(err)}
 if !reflect.DeepEqual(f.events,[]string{"host","state","state"}){t.Fatal(f.events)}
}

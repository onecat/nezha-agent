package report

import (
 "context"
 "errors"
 "testing"
 "time"
 pb "github.com/onecat/nezha-agent/proto"
)

type ipFixture struct {
 fixture
 ip string
 ipErr error
 reported string
 geo string
}
func(f *ipFixture) Lookup(context.Context)(string,error){return f.ip,f.ipErr}
func(f *ipFixture) ReportHost(ctx context.Context,h *pb.Host)error{
 f.reported=h.GetIp()
 return f.fixture.ReportHost(ctx,h)
}
func(f *ipFixture) LookupGeoIP(_ context.Context,ip string)error{
 f.geo=ip
 return errors.New("GeoIP unavailable")
}
func TestIPReportingDoesNotBlockState(t *testing.T){
 f:=&ipFixture{ip:"8.8.8.8/2606:4700::1111"}
 l:=Loop{Collector:f,Dashboard:f,Version:"v0.30.00",Interval:time.Second,IPSource:f,GeoLookup:f,PreferIPv6Geo:true}
 var next time.Time
 var cache string
 if err:=l.onceWithIP(context.Background(),&next,&cache);err!=nil {t.Fatal(err)}
 if f.reported!=f.ip || f.geo!="2606:4700::1111" || len(f.events)!=2 {t.Fatalf("unexpected report: %+v",f)}
 f.ip=""
 f.ipErr=errors.New("network failure")
 next=time.Time{}
 if err:=l.onceWithIP(context.Background(),&next,&cache);err!=nil{t.Fatal(err)}
 if f.reported!="8.8.8.8/2606:4700::1111"{t.Fatal("lost last successful IP")}
 f.ipErr=nil
 next=time.Time{}
 if err:=l.onceWithIP(context.Background(),&next,&cache);err!=nil{t.Fatal(err)}
 if f.reported!=""{t.Fatal("disabled discovery did not clear IP")}
}

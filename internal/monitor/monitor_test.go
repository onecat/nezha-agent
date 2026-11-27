package monitor

import (
 "context"
 "fmt"
 "math"
 "github.com/shirou/gopsutil/v4/host"
 "testing"
 "time"
)

func TestSpeed(t *testing.T){
 for _,v:=range []struct{old,current uint64; seconds float64; want uint64}{
  {100,300,2,100},{300,100,2,0},{0,100,0,0},{0,100,-1,0},{100,100,2,0},
 } {
  if n:=speed(v.old,v.current,v.seconds);n!=v.want { t.Fatalf("got %d want %d",n,v.want) }
 }
}

func TestLocalSample(t *testing.T){
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second)
 defer cancel()
 c:=new(Collector)
 h,err:=c.Host(ctx,"v0.30.00")
 if err!=nil { t.Fatal(err) }
 if h.Version!="v0.30.00" || h.IP!="" || h.CountryCode!="" || h.MemTotal==0 || h.DiskTotal==0 || h.Arch=="" { t.Fatal("invalid host sample") }
 s,err:=c.State(ctx)
 if err!=nil { t.Fatal(err) }
 if s.CPU<0 || s.CPU>100 || s.NetInSpeed!=0 || s.NetOutSpeed!=0 || math.IsNaN(s.Load1) || math.IsInf(s.Load1,0) || s.Load1<0 || s.Load5<0 || s.Load15<0 { t.Fatal("invalid initial state sample") }
 if _,err:=c.State(ctx);err!=nil { t.Fatal(err) }
}

func TestFiniteNonnegative(t *testing.T){
 for _,v:=range []float64{math.NaN(),math.Inf(1),math.Inf(-1),-1}{
  if got:=finiteNonnegative(v);got!=0{t.Fatalf("invalid load %v became %v",v,got)}
 }
 if got:=finiteNonnegative(2.5);got!=2.5{t.Fatal(got)}
}

func TestNormalizeTemperatures(t *testing.T){
 readings:=[]host.TemperatureStat{
  {SensorKey:" cpu ",Temperature:44},
  {SensorKey:"cpu",Temperature:46},
  {SensorKey:"",Temperature:40},
  {SensorKey:"bad",Temperature:math.NaN()},
  {SensorKey:"hot",Temperature:300},
  {SensorKey:"cold",Temperature:-101},
  {SensorKey:"gpu",Temperature:55},
 }
 got:=normalizeTemperatures(readings)
 if len(got)!=2||got[0].Name!="cpu"||got[0].Temperature!=44||got[1].Name!="gpu"{
  t.Fatalf("unexpected sensors: %+v",got)
 }
 many:=make([]host.TemperatureStat,100)
 for i:=range many{many[i]=host.TemperatureStat{SensorKey:fmt.Sprintf("sensor-%03d",i),Temperature:40}}
 if len(normalizeTemperatures(many))!=64{t.Fatal("unbounded sensors")}
}

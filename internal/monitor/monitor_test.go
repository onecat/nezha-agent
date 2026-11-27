package monitor

import (
 "context"
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
 if s.CPU<0 || s.CPU>100 || s.NetInSpeed!=0 || s.NetOutSpeed!=0 { t.Fatal("invalid initial state sample") }
 if _,err:=c.State(ctx);err!=nil { t.Fatal(err) }
}

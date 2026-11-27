package main

import (
 "context"
 "errors"
 "flag"
 "fmt"
 "log"
 "os"
 "os/signal"
 "syscall"

 "github.com/onecat/nezha-agent/internal/config"
 "github.com/onecat/nezha-agent/internal/dashboard"
 "github.com/onecat/nezha-agent/internal/ipquery"
 "github.com/onecat/nezha-agent/internal/monitor"
 "github.com/onecat/nezha-agent/internal/report"
)

// Version is set at build time by the release pipeline. The default is the development baseline.
var version="v0.30.00"


func run(ctx context.Context,path string,ready func()error)error{
 cfg,err:=config.Load(path)
 if err!=nil{return err}
 pool,err:=config.Roots(cfg.CAFile)
 if err!=nil{return err}
 c,err:=dashboard.New(dashboard.Config{Address:cfg.Address,Secret:cfg.Secret,RootCAs:pool})
 if err!=nil{return err}
 defer c.Close()
 q,err:=ipquery.New(cfg.IP)
 if err!=nil{return err}
 l:=report.Loop{Collector:&monitor.Collector{ExcludedInterfaces:cfg.ExcludedInterfaces},Dashboard:c,Version:version,Interval:cfg.Interval,
  IPSource:q,GeoLookup:c,PreferIPv6Geo:cfg.PreferIPv6Geo,OnReady:ready,
  OnFailure:func(){log.Print("monitor reporting failed; retrying")},
  OnIPFailure:func(){log.Print("IP discovery or GeoIP lookup unavailable")},
 }
 return l.Run(ctx)
}
func main(){
 path:=flag.String("config","agent.json","local private configuration file")
 showVersion:=flag.Bool("version",false,"print version")
 supervised:=flag.Bool("supervised",false,"use private supervisor pipes (Linux only)")
 flag.Parse()
 if *showVersion {fmt.Println(version);return}
 if flag.NArg()!=0{log.Print("unexpected arguments");os.Exit(2)}
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer stop()
 ready,closePipes,err:=supervisorPipes(ctx,stop,*supervised)
 if err!=nil{log.Print(err);os.Exit(1)}
 defer closePipes()
 if err:=run(ctx,*path,ready);err!=nil && !errors.Is(err,context.Canceled){log.Print(err);os.Exit(1)}
}

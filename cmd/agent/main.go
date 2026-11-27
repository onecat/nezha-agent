package main

import (
 "context"
 "crypto/x509"
 "errors"
 "flag"
 "fmt"
 "io"
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

const version="v0.30.00"

func roots(path string)(*x509.CertPool,error){
 if path=="" {return nil,nil}
 f,err:=os.Open(path)
 if err!=nil{return nil,errors.New("cannot open CA file")}
 defer f.Close()
 info,err:=f.Stat()
 if err!=nil || !info.Mode().IsRegular(){return nil,errors.New("invalid CA file")}
 b,err:=io.ReadAll(io.LimitReader(f,1024*1024+1))
 if err!=nil || len(b)>1024*1024{return nil,errors.New("invalid CA file size")}
 p:=x509.NewCertPool()
 if !p.AppendCertsFromPEM(b){return nil,errors.New("CA file contains no valid certificates")}
 return p,nil
}

func run(ctx context.Context,path string)error{
 cfg,err:=config.Load(path)
 if err!=nil{return err}
 pool,err:=roots(cfg.CAFile)
 if err!=nil{return err}
 c,err:=dashboard.New(dashboard.Config{Address:cfg.Address,Secret:cfg.Secret,RootCAs:pool})
 if err!=nil{return err}
 defer c.Close()
 q,err:=ipquery.New(cfg.IP)
 if err!=nil{return err}
 l:=report.Loop{Collector:new(monitor.Collector),Dashboard:c,Version:version,Interval:cfg.Interval,
  IPSource:q,GeoLookup:c,PreferIPv6Geo:cfg.PreferIPv6Geo,
  OnFailure:func(){log.Print("monitor reporting failed; retrying")},
  OnIPFailure:func(){log.Print("IP discovery or GeoIP lookup unavailable")},
 }
 return l.Run(ctx)
}
func main(){
 path:=flag.String("config","agent.json","local private configuration file")
 showVersion:=flag.Bool("version",false,"print version")
 flag.Parse()
 if *showVersion {fmt.Println(version);return}
 if flag.NArg()!=0{log.Print("unexpected arguments");os.Exit(2)}
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer stop()
 if err:=run(ctx,*path);err!=nil && !errors.Is(err,context.Canceled){log.Print(err);os.Exit(1)}
}

//go:build linux

package main

import (
 "context"
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "io"
 "log"
 "os"
 "os/signal"
 "path/filepath"
 "runtime"
 "syscall"
 "time"

 "github.com/onecat/nezha-agent/internal/config"
 "github.com/onecat/nezha-agent/internal/dashboard"
 "github.com/onecat/nezha-agent/internal/managedupgrade"
 "github.com/onecat/nezha-agent/internal/upgradestate"
 "github.com/onecat/nezha-agent/internal/upgradesupervisor"
 "github.com/onecat/nezha-agent/internal/worker"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)

type settings struct{
 Enabled bool `json:"enabled"`
 ServerID uint64 `json:"server_id"`
 InitialSequence uint64 `json:"initial_sequence"`
 InitialVersion string `json:"initial_version"`
 AgentConfig string `json:"agent_config"`
 InstallDir string `json:"install_dir"`
 StateDir string `json:"state_dir"`
 StageDir string `json:"stage_dir"`
 Keys map[string]string `json:"keys"`
}

func load(path string)(settings,map[string]ed25519.PublicKey,error){
 var cfg settings
 if !filepath.IsAbs(path){return cfg,nil,errors.New("absolute supervisor config required")}
 before,err:=os.Lstat(path)
 if err!=nil||!before.Mode().IsRegular()||before.Mode().Perm()&0077!=0{return cfg,nil,errors.New("private supervisor config required")}
 f,err:=os.Open(path)
 if err!=nil{return cfg,nil,err}
 defer f.Close()
 st,err:=f.Stat()
 if err!=nil||!os.SameFile(before,st)||st.Size()>32768{return cfg,nil,errors.New("invalid supervisor config")}
 d:=json.NewDecoder(io.LimitReader(f,32769));d.DisallowUnknownFields()
 if err:=d.Decode(&cfg);err!=nil{return cfg,nil,errors.New("invalid supervisor settings")}
 if err:=d.Decode(new(any));err!=io.EOF{return cfg,nil,errors.New("trailing settings")}
 if !cfg.Enabled||cfg.ServerID==0||cfg.InitialSequence==0||len(cfg.Keys)==0||len(cfg.Keys)>16||
  (runtime.GOARCH!="amd64"&&runtime.GOARCH!="arm64"){return cfg,nil,errors.New("supervisor not enabled or provisioned")}
 for _,p:=range []string{cfg.AgentConfig,cfg.InstallDir,cfg.StateDir,cfg.StageDir}{
  if !filepath.IsAbs(p){return cfg,nil,errors.New("absolute local paths required")}
 }
 if filepath.Clean(cfg.StateDir)==filepath.Clean(cfg.StageDir)||filepath.Clean(cfg.InstallDir)==filepath.Clean(cfg.StageDir){return cfg,nil,errors.New("dedicated staging directory required")}
 st,err=os.Lstat(cfg.StageDir)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0077!=0{return cfg,nil,errors.New("private staging directory required")}
 keys:=map[string]ed25519.PublicKey{}
 for id,h:=range cfg.Keys{
  b,err:=hex.DecodeString(h)
  if id==""||err!=nil||len(b)!=ed25519.PublicKeySize{return cfg,nil,errors.New("invalid trusted key")}
  keys[id]=ed25519.PublicKey(b)
 }
 return cfg,keys,nil
}
func isTerminal(t *core.Transaction)bool{
 if t==nil{return false}
 switch t.State{case core.StateSucceeded,core.StateRolledBack,core.StateFailed:return true}
 return false
}
func run(ctx context.Context,cfg settings,keys map[string]ed25519.PublicKey)error{
 ledger,err:=upgradestate.Open(cfg.StateDir,cfg.ServerID)
 if err!=nil{return err}
 defer ledger.Close()
 agent,err:=config.Load(cfg.AgentConfig)
 if err!=nil{return err}
 if agent.CAFile!=""&&!filepath.IsAbs(agent.CAFile){return errors.New("absolute Agent CA path required")}
 roots,err:=config.Roots(agent.CAFile)
 if err!=nil{return err}
 client,err:=dashboard.New(dashboard.Config{Address:agent.Address,Secret:agent.Secret,RootCAs:roots})
 if err!=nil{return err}
 defer client.Close()
 p,err:=worker.New(cfg.InstallDir,cfg.AgentConfig)
 if err!=nil{return err}
 defer func(){
  stop,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
  if err:=p.Stop(stop);err!=nil{log.Print("worker stop requires service-manager cleanup")}
 }()
 sup,err:=upgradesupervisor.New(ledger,cfg.InstallDir,p)
 if err!=nil{return err}
 runner,err:=managedupgrade.New(true,client,ledger,sup,cfg.ServerID,cfg.StageDir,keys)
 if err!=nil{return err}
 current,previous,_,err:=ledger.VersionInfo()
 if err!=nil{return err}
 _,task,err:=ledger.Snapshot()
 if err!=nil{return err}
 if task!=nil&&!isTerminal(task){
  if _,err:=sup.Recover(previous);err!=nil{return err}
 }else{
  start,cancel:=context.WithTimeout(ctx,60*time.Second)
  err=p.Start(start)
  if err==nil{err=p.Healthy(start,current)}
  cancel()
  if err!=nil{return err}
 }
 for {
  if err:=ctx.Err();err!=nil{return err}
  if !p.Alive(){return errors.New("Agent worker exited")}
  current,_,reported,err:=ledger.VersionInfo()
  if err!=nil{return err}
  _,task,err:=ledger.Snapshot()
  if err!=nil{return err}
  if task!=nil&&!isTerminal(task){return errors.New("upgrade requires startup recovery")}
  if task!=nil&&!reported{
   if err:=runner.RetryResult();err!=nil{log.Print("upgrade receipt unresolved; new tasks paused")}
  }else{
   if _,err:=runner.RunOnce(ctx,current);err!=nil&&status.Code(err)!=codes.NotFound&&status.Code(err)!=codes.Unavailable{
    log.Print("managed upgrade did not complete; checking durable state")
   }
  }
  timer:=time.NewTimer(15*time.Second)
  select{case <-ctx.Done():timer.Stop();return ctx.Err();case <-timer.C:}
 }
}
func main(){
 path:=flag.String("config","","private supervisor configuration")
 initialize:=flag.Bool("initialize",false,"provision a new local ledger once")
 flag.Parse()
 if flag.NArg()!=0{log.Fatal("unexpected arguments")}
 cfg,keys,err:=load(*path)
 if err!=nil{log.Fatal("invalid or disabled supervisor provisioning")}
 if *initialize{
  s,err:=upgradestate.InitializeVersion(cfg.StateDir,cfg.ServerID,cfg.InitialSequence,cfg.InitialVersion)
  if err!=nil{log.Fatal("ledger initialization refused")}
  if err:=s.Close();err!=nil{log.Fatal("ledger close failed")}
  return
 }
 ctx,cancel:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM)
 defer cancel()
 if err:=run(ctx,cfg,keys);err!=nil&&!errors.Is(err,context.Canceled){log.Fatal("supervisor stopped: local recovery or configuration required")}
}

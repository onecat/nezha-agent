//go:build linux

package main

import (
 "context"
 "crypto/ed25519"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "log"
 "io"
 "net"
 "os"
 "path/filepath"
 "runtime"
 "time"

 "github.com/onecat/nezha-agent/internal/config"
 "github.com/onecat/nezha-agent/internal/dashboard"
 "github.com/onecat/nezha-agent/internal/upgradeinstall"
 "github.com/onecat/nezha-agent/internal/upgradestate"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
)

const installRoot="/opt/nezha/agent"
const configName="agent.json"
const recoveryName=".agent-recovery"
const attemptName=".upgrade-attempt"
type enrollment struct{
 ServerID uint64 `json:"server_id"`
 PublicKey string `json:"public_key"`
}
func isDirectConfig(path string)bool{return filepath.Clean(path)==filepath.Join(installRoot,configName)}
func directPaths(root string)(string,string,string){return filepath.Join(root,configName),filepath.Join(root,".state"),filepath.Join(root,".stage")}
func readPrivate(path string,max int64)([]byte,error){
 st,err:=os.Lstat(path);if err!=nil{return nil,err}
 if !st.Mode().IsRegular()||st.Mode().Perm()&0077!=0||st.Size()>max{return nil,errors.New("invalid private file")}
 f,err:=os.Open(path);if err!=nil{return nil,err};defer f.Close()
 actual,err:=f.Stat();if err!=nil||!os.SameFile(st,actual){return nil,errors.New("private file changed")}
 b,err:=io.ReadAll(io.LimitReader(f,max+1));if err!=nil||int64(len(b))>max{return nil,errors.New("invalid private file size")};return b,nil
}
func openDirect(root string)(*upgradestate.Store,map[string]ed25519.PublicKey,uint64,error){
 _,state,_:=directPaths(root)
 b,err:=readPrivate(filepath.Join(state,"identity.json"),4096);if err!=nil{return nil,nil,0,err}
 var e enrollment
 if err:=json.Unmarshal(b,&e);err!=nil{return nil,nil,0,err}
 k,err:=hex.DecodeString(e.PublicKey);if err!=nil||len(k)!=ed25519.PublicKeySize||e.ServerID==0{return nil,nil,0,errors.New("invalid pinned identity")}
 ledger,err:=upgradestate.Open(state,e.ServerID)
 return ledger,map[string]ed25519.PublicKey{"dashboard-local":ed25519.PublicKey(k)},e.ServerID,err
}
func terminalDirect(t *core.Transaction)bool{return t==nil||t.State==core.StateSucceeded||t.State==core.StateFailed||t.State==core.StateRolledBack}
func syncDirDirect(dir string)error{f,err:=os.Open(dir);if err!=nil{return err};defer f.Close();return f.Sync()}
func atomicFile(path string,b []byte,mode os.FileMode)error{
 dir:=filepath.Dir(path);f,err:=os.CreateTemp(dir,".agent-write-");if err!=nil{return err};defer os.Remove(f.Name());defer f.Close()
 if err=f.Chmod(mode);err!=nil{return err}
 if _,err=f.Write(b);err!=nil{return err}
 if err=f.Sync();err!=nil{return err};if err=f.Close();err!=nil{return err}
 if err=os.Rename(f.Name(),path);err!=nil{return err};return syncDirDirect(dir)
}
// systemd runs this short-lived command from the retained old executable
// before EVERY service start. The first candidate launch gets exactly one
// attempt. A failed exec, timeout, crash or interrupted launch restores old
// bytes on the next start, before systemd executes the main binary.
func prepareDirect(root string)error{
 l,_,_,err:=openDirect(root);if err!=nil{return err};defer l.Close()
 return prepareLedger(root,l,time.Now())
}
func prepareLedger(root string,l *upgradestate.Store,now time.Time)error{
 _,t,err:=l.Snapshot();if err!=nil{return err}
 marker:=filepath.Join(root,attemptName)
 if terminalDirect(t){if err:=os.Remove(marker);err!=nil&&!os.IsNotExist(err){return err};return nil}
 switch t.State{
 case core.StateVerified:
  _,err=l.Advance(*t,core.StateFailed,now);return err
 case core.StateHealthCheck:
  b,err:=readPrivate(marker,256)
  if os.IsNotExist(err)&&now.Before(t.ExpiresAt){return atomicFile(marker,[]byte(t.ID),0600)}
  if err!=nil&&!os.IsNotExist(err){return err}
  if err==nil&&string(b)!=t.ID{return errors.New("upgrade attempt identity mismatch")}
 case core.StateInstalling,core.StateRollingBack:
 default:return errors.New("invalid direct recovery state")
 }
 i,err:=upgradeinstall.New(root,l);if err!=nil{return err}
 _,err=i.Restore(*t,now);return err
}
func sdReady()error{
 addr:=os.Getenv("NOTIFY_SOCKET");if addr==""{return errors.New("systemd notify socket missing")}
 if addr[0]=='@'{addr="\x00"+addr[1:]}
 c,err:=net.DialUnix("unixgram",nil,&net.UnixAddr{Name:addr,Net:"unixgram"});if err!=nil{return err};defer c.Close()
 if err:=c.SetWriteDeadline(time.Now().Add(5*time.Second));err!=nil{return err}
 _,err=c.Write([]byte("READY=1"));return err
}
func completeHealth(l *upgradestate.Store,actual string,now time.Time)error{
 current,_,_,err:=l.VersionInfo();if err!=nil{return err}
 _,t,err:=l.Snapshot();if err!=nil{return err}
 if terminalDirect(t){if current!=actual{return errors.New("installed version differs from ledger")};return nil}
 switch t.State{
 case core.StateHealthCheck:
  if actual!=t.Version{return errors.New("candidate version mismatch")}
  _,err=l.Advance(*t,core.StateSucceeded,now);return err
 case core.StateRollingBack:
  if actual!=current{return errors.New("rollback version mismatch")}
  _,err=l.Advance(*t,core.StateRolledBack,now);return err
 default:return errors.New("unexpected startup state")
 }
}
func checkStartupVersion(l *upgradestate.Store,actual string)error{
 current,_,_,err:=l.VersionInfo();if err!=nil{return err}
 _,t,err:=l.Snapshot();if err!=nil{return err}
 if t!=nil&&t.State==core.StateHealthCheck{if actual!=t.Version{return errors.New("candidate version mismatch")};return nil}
 if current!=actual{return errors.New("installed version differs from ledger")}
 return nil
}
func refreshRecovery(root string)error{
 // Same executable inode, not a second independently installed program.
 tmp:=filepath.Join(root,".recovery-new")
 if err:=os.Remove(tmp);err!=nil&&!os.IsNotExist(err){return err}
 if err:=os.Link(filepath.Join(root,"nezha-agent"),tmp);err!=nil{return err}
 defer os.Remove(tmp)
 if err:=os.Rename(tmp,filepath.Join(root,recoveryName));err!=nil{return err}
 return syncDirDirect(root)
}
func runDirect(ctx context.Context,path string)error{
 root:=filepath.Dir(path)
 l,keys,id,err:=openDirect(root);if err!=nil{return err};defer l.Close()
 if err:=checkStartupVersion(l,version);err!=nil{return err}
 cfg,err:=config.Load(path);if err!=nil{return err}
 roots,err:=config.Roots(cfg.CAFile);if err!=nil{return err}
 c,err:=dashboard.New(dashboard.Config{Address:cfg.Address,Secret:cfg.Secret,RootCAs:roots});if err!=nil{return err};defer c.Close()
 monitorCtx,cancel:=context.WithCancel(ctx);defer cancel()
 ready:=make(chan struct{})
 done:=make(chan error,1)
 go func(){done<-run(monitorCtx,path,func()error{
  if err:=completeHealth(l,version,time.Now());err!=nil{return err}
  if err:=sdReady();err!=nil{return err}
  close(ready);return nil
 })}()
 select{case <-ctx.Done():return ctx.Err();case err:=<-done:return err;case <-ready:}
 defer func(){cancel()}()
 for{
  _,t,err:=l.Snapshot();if err!=nil{return err}
  _,_,reported,err:=l.VersionInfo();if err!=nil{return err}
  if !terminalDirect(t){return errors.New("recovery required")}
  if t!=nil&&!reported{
   if err:=c.ReportUpgradeResult(ctx,*t);err==nil{if err:=l.MarkReported(*t);err!=nil{return err}}
  }else{
   restart,err:=directUpgrade(ctx,root,l,c,id,keys,version)
   if restart{return err}
   if err!=nil&&status.Code(err)!=codes.NotFound&&status.Code(err)!=codes.Unavailable{log.Print("upgrade request deferred")}
  }
  timer:=time.NewTimer(10*time.Second)
  select{case <-ctx.Done():timer.Stop();return ctx.Err();case err:=<-done:timer.Stop();return err;case <-timer.C:}
 }
}
func directUpgrade(ctx context.Context,root string,l *upgradestate.Store,c *dashboard.Client,id uint64,keys map[string]ed25519.PublicKey,current string)(bool,error){
 high,_,err:=l.Snapshot();if err!=nil{return true,err}
 _,_,stage:=directPaths(root)
 d,err:=c.DownloadUpgrade(ctx,stage,id,current,"linux",runtime.GOARCH,high,keys);if err!=nil{return false,err};defer d.Close()
 t:=d.Task()
 if err:=c.AcknowledgeVerified(ctx,d);err!=nil{return false,err}
 if err:=l.ReserveVerified(t,d.Package(),"linux",runtime.GOARCH,current,time.Now());err!=nil{return true,err}
 if err:=c.RequestInstallGrant(ctx,d);err!=nil{_,save:=l.Advance(t,core.StateFailed,time.Now());return save!=nil,errors.Join(err,save)}
 // Before changing the running pathname, persist the known-good recovery
 // inode. Linux permits atomic replacement of a running executable.
 if err:=refreshRecovery(root);err!=nil{return true,err}
 marker:=filepath.Join(root,attemptName)
 if err:=os.Remove(marker);err!=nil&&!os.IsNotExist(err){return true,err}
 if err:=syncDirDirect(root);err!=nil{return true,err}
 i,err:=upgradeinstall.New(root,l);if err!=nil{return true,err}
 next,err:=i.Install(t,d,d.Size(),keys,time.Now())
 if err!=nil{return true,err}
 if next.State!=core.StateHealthCheck{return true,fmt.Errorf("unexpected installation state")}
 // Normal exit; systemd restarts the direct Agent after ExecStartPre.
 return true,nil
}

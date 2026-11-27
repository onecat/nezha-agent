//go:build linux

package main

import(
 "bytes"
 "context"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "os"
 "os/exec"
 "os/user"
 "path/filepath"
 "runtime"
 "strconv"
 "strings"
 "syscall"
 "time"

 "github.com/onecat/nezha-agent/internal/config"
 "github.com/onecat/nezha-agent/internal/dashboard"
 "github.com/onecat/nezha-agent/internal/upgradestate"
 "golang.org/x/sys/unix"
)

const serviceName="nezha-agent.service"
const unitPath="/etc/systemd/system/nezha-agent.service"
const serviceAccount="nezha-agent"
const unitText=`[Unit]
Description=Nezha Agent
Wants=network-online.target
After=network-online.target
[Service]
Type=notify
NotifyAccess=main
User=nezha-agent
UMask=0077
ExecStartPre=/opt/nezha/agent/.agent-recovery service prepare
ExecStart=/opt/nezha/agent/nezha-agent --config /opt/nezha/agent/agent.json
Restart=always
RestartSec=5s
TimeoutStartSec=60s
TimeoutStopSec=30s
KillMode=control-group
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/nezha/agent
[Install]
WantedBy=multi-user.target
`
func systemctl(args ...string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),90*time.Second);defer cancel()
 c:=exec.CommandContext(ctx,"/usr/bin/systemctl",args...);c.Stdout=os.Stdout;c.Stderr=os.Stderr
 return c.Run()
}
func systemValue(args ...string)string{
 ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);defer cancel()
 b,err:=exec.CommandContext(ctx,"/usr/bin/systemctl",args...).Output();if err!=nil{return ""};return strings.TrimSpace(string(b))
}
func present(p string)bool{_,err:=os.Lstat(p);return !os.IsNotExist(err)}
func trustedDir(p string,uid uint32)error{
 st,err:=os.Lstat(p);if err!=nil{return err}
 info,ok:=st.Sys().(*syscall.Stat_t)
 if !ok||!st.IsDir()||st.Mode().Perm()&0022!=0||info.Uid!=uid{return fmt.Errorf("untrusted directory: %s",p)}
 return nil
}
func rootLock()(*os.File,error){
 if os.Geteuid()!=0||runtime.GOARCH!="amd64"{return nil,errors.New("root on Linux amd64 required")}
 if !present("/run/systemd/system"){return nil,errors.New("systemd required")}
 f,err:=os.OpenFile("/run/nezha-agent-install.lock",os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW,0600);if err!=nil{return nil,err}
 if err=unix.Flock(int(f.Fd()),unix.LOCK_EX|unix.LOCK_NB);err!=nil{f.Close();return nil,errors.New("another installation in progress")}
 return f,nil
}
func account()(uint32,uint32,error){
 u,err:=user.Lookup(serviceAccount)
 if err!=nil{
  if err:=exec.Command("/usr/sbin/useradd","--system","--user-group","--no-create-home","--home-dir","/nonexistent","--shell","/usr/sbin/nologin",serviceAccount).Run();err!=nil{return 0,0,err}
  u,err=user.Lookup(serviceAccount);if err!=nil{return 0,0,err}
 }
 uid,e:=strconv.ParseUint(u.Uid,10,32);gid,e2:=strconv.ParseUint(u.Gid,10,32)
 if e!=nil||e2!=nil||uid==0||gid==0{return 0,0,errors.New("invalid service account")}
 return uint32(uid),uint32(gid),nil
}
func readSecret() (string,error){
 b,err:=io.ReadAll(io.LimitReader(os.Stdin,1026));if err!=nil{return "",err}
 s:=strings.TrimSuffix(string(b),"\n")
 if len(s)<1||len(s)>1024{return "",errors.New("invalid Agent secret")}
 for _,c:=range s{if c<33||c>126{return "",errors.New("invalid Agent secret")}}
 return s,nil
}
func validEndpoint(s string)bool{
 h,p,err:=net.SplitHostPort(s);if err!=nil||h==""||strings.ContainsAny(h," /\\@?#\r\n\t"){return false}
 n,err:=strconv.Atoi(p);return err==nil&&n>0&&n<=65535
}
func serviceCommand(args []string)error{
 if len(args)==0{return errors.New("service install|reinstall|uninstall|status|restart")}
 switch args[0]{
 case "prepare":
  if os.Geteuid()==0{return errors.New("prepare must run as service user")};return prepareDirect(installRoot)
 case "status","restart","stop","start":
  if len(args)!=1{return errors.New("unexpected arguments")};return systemctl(args[0],serviceName)
 case "uninstall":
  lock,err:=rootLock();if err!=nil{return err};defer lock.Close()
  if len(args)!=1{return errors.New("unexpected arguments")}
  if err:=systemctl("disable","--now",serviceName);err!=nil{return err}
  if err:=os.Remove(unitPath);err!=nil&&!os.IsNotExist(err){return err}
  // Preserve config, identity, installed bytes and ledger for reinstallation.
  return systemctl("daemon-reload")
 case "install","reinstall","provision","repair":
  flags:=flag.NewFlagSet("service",flag.ContinueOnError)
  server:=flags.String("server","","TLS endpoint")
  ca:=flags.String("ca-file","","private CA PEM")
  from:=flags.String("from","","internal verified source")
  if err:=flags.Parse(args[1:]);err!=nil{return err}
  if flags.NArg()!=0||!validEndpoint(*server){return errors.New("valid --server required")}
  secret,err:=readSecret();if err!=nil{return err}
  if args[0]=="provision"||args[0]=="repair"{
   if os.Geteuid()==0{return errors.New("provision/repair must run as service user")}
   if args[0]=="provision"{return provision(*server,secret,*ca)}
   return repair(*server,secret,*from)
  }
  if *from!=""{return errors.New("unexpected source")}
  return installService(*server,secret,*ca)
 default:return errors.New("unknown service command")
 }
}
func copyAgent(src,dst string,mode os.FileMode)error{
 f,err:=os.Open(src);if err!=nil{return err};defer f.Close()
 st,err:=f.Stat();if err!=nil||!st.Mode().IsRegular()||st.Size()<1||st.Size()>100<<20{return errors.New("invalid executable")}
 b,err:=io.ReadAll(io.LimitReader(f,100<<20+1));if err!=nil||int64(len(b))!=st.Size(){return errors.New("executable read failed")}
 return atomicFile(dst,b,mode)
}
func provision(endpoint,secret,ca string)error{
 root:=installRoot;path,state,stage:=directPaths(root)
 for _,p:=range []string{state,stage}{if err:=os.Mkdir(p,0700);err!=nil{return err}}
 cfg:=map[string]any{"server":endpoint,"client_secret":secret}
 if ca!=""{cfg["ca_file"]=ca}
 b,err:=json.MarshalIndent(cfg,"","  ");if err!=nil{return err}
 if _,err:=config.Decode(b);err!=nil{return err}
 if err:=atomicFile(path,b,0600);err!=nil{return err}
 roots,err:=config.Roots(ca);if err!=nil{return err}
 client,err:=dashboard.New(dashboard.Config{Address:endpoint,Secret:secret,RootCAs:roots});if err!=nil{return err};defer client.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 e,err:=client.EnrollUpgrade(ctx);if err!=nil{return errors.New("Dashboard enrollment refused")}
 data,err:=json.Marshal(enrollment{ServerID:e.ServerID,PublicKey:hex.EncodeToString(e.Key)});if err!=nil{return err}
 l,err:=upgradestate.InitializeVersion(state,e.ServerID,1,version);if err!=nil{return err}
 if err:=l.Close();err!=nil{return err}
 if err:=atomicFile(filepath.Join(state,"identity.json"),data,0600);err!=nil{return err}
 return refreshRecovery(root)
}
func repair(endpoint,secret,src string)error{
 path,_,_:=directPaths(installRoot)
 cfg,err:=config.Load(path);if err!=nil{return err}
 if cfg.Address!=endpoint||cfg.Secret!=secret{return errors.New("existing Agent identity differs")}
 l,_,_,err:=openDirect(installRoot);if err!=nil{return err};defer l.Close()
 current,_,reported,err:=l.VersionInfo();if err!=nil{return err}
 _,t,err:=l.Snapshot();if err!=nil{return err}
 if !terminalDirect(t)||t!=nil&&!reported{return errors.New("unresolved upgrade; repair refused")}
 if current!=version{return errors.New("reinstall requires exact installed release; use Dashboard upgrade first")}
 if err:=copyAgent(src,filepath.Join(installRoot,"nezha-agent"),0700);err!=nil{return err}
 return refreshRecovery(installRoot)
}
func invokeAs(uid,gid uint32,exe string,args []string,secret string)error{
 ctx,cancel:=context.WithTimeout(context.Background(),60*time.Second);defer cancel()
 c:=exec.CommandContext(ctx,exe,args...)
 c.SysProcAttr=&syscall.SysProcAttr{Credential:&syscall.Credential{Uid:uid,Gid:gid,Groups:[]uint32{}}}
 c.Stdin=strings.NewReader(secret+"\n");c.Stdout=os.Stdout;c.Stderr=os.Stderr
 c.Env=[]string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
 return c.Run()
}
func installService(endpoint,secret,ca string)(retErr error){
 lock,err:=rootLock();if err!=nil{return err};defer lock.Close()
 parent:=filepath.Dir(installRoot)
 if err:=trustedDir("/opt",0);err!=nil{return err}
 if err:=os.Mkdir(parent,0755);err!=nil&&!os.IsExist(err){return err}
 if err:=trustedDir(parent,0);err!=nil{return err}
 if present("/etc/nezha/supervisor.json")||present("/var/lib/nezha-agent/state/upgrade-state.json")||systemValue("is-active","nezha-supervisor.service")=="active"||systemValue("is-enabled","nezha-supervisor.service")=="enabled"{return errors.New("standalone managed installation requires explicit migration")}
 if systemValue("show","-p","DropInPaths","--value",serviceName)!=""{return errors.New("service drop-ins require review")}
 // Existing v0.30.09 managed ledger cannot be discarded by a legacy migration.
 if present(filepath.Join(installRoot,"managed")){return errors.New("previous managed layout requires explicit ledger-preserving migration")}
 uid,gid,err:=account();if err!=nil{return err}
 existing:=present(installRoot);direct:=false
 if existing{
  if trustedDir(installRoot,uid)==nil{direct=true}else if err:=trustedDir(installRoot,0);err!=nil{return err}
 }
 active:=systemValue("is-active",serviceName)=="active"
 enabled:=systemValue("is-enabled",serviceName)=="enabled"
 exe,err:=os.Executable();if err!=nil{return err}
 // Copy verified bootstrap into a root-owned staging directory before
 // executing as the service user. No root writes through service-owned paths.
 stage,err:=os.MkdirTemp(parent,".agent-bootstrap-");if err!=nil{return err};defer os.RemoveAll(stage)
 if err:=os.Chmod(stage,0755);err!=nil{return err}
 bootstrap:=filepath.Join(stage,"agent");if err:=copyAgent(exe,bootstrap,0755);err!=nil{return err}
 oldUnit,unitErr:=os.ReadFile(unitPath)
 if unitErr!=nil&&!os.IsNotExist(unitErr){return unitErr}
 if active||direct{if err:=systemctl("stop",serviceName);err!=nil{return err}}
 if direct{
  defer func(){if retErr!=nil&&active{_ =systemctl("start",serviceName)}}()
  if err:=invokeAs(uid,gid,bootstrap,[]string{"service","repair","--server",endpoint,"--from",bootstrap},secret);err!=nil{return err}
 }else{
  backup,err:=os.MkdirTemp(parent,".agent-backup-");if err!=nil{return err}
  moved,created,launched:=false,false,false
  defer func(){
   if retErr==nil{fmt.Println("Previous files retained in",backup);return}
   _=systemctl("stop",serviceName)
   // Once started, a task could have been granted. Preserve the candidate
   // tree and ledger rather than erasing it; the old directory remains safe.
   if launched{fmt.Println("New ledger retained for recovery; previous files in",backup);return}
   if created{_ =os.Rename(installRoot,filepath.Join(backup,"failed-new-agent"))}
   if moved{_ =os.Rename(filepath.Join(backup,"old-agent"),installRoot)}
   if unitErr==nil{_ =atomicFile(unitPath,oldUnit,0644)}else{_ =os.Remove(unitPath)}
   _ =systemctl("daemon-reload")
   if enabled{_ =systemctl("enable",serviceName)}else{_ =systemctl("disable",serviceName)}
   if active{_ =systemctl("start",serviceName)}
  }()
  if unitErr==nil{if err:=atomicFile(filepath.Join(backup,"old-unit"),oldUnit,0600);err!=nil{return err}}
  if existing{if err:=os.Rename(installRoot,filepath.Join(backup,"old-agent"));err!=nil{return err};moved=true}
  if err:=os.Mkdir(installRoot,0700);err!=nil{return err};created=true
  if err:=copyAgent(bootstrap,filepath.Join(installRoot,"nezha-agent"),0700);err!=nil{return err}
  if err:=os.Chown(filepath.Join(installRoot,"nezha-agent"),int(uid),int(gid));err!=nil{return err}
  localCA:=""
  if ca!=""{
   b,err:=os.ReadFile(ca);if err!=nil||len(b)>1<<20{return errors.New("invalid CA file")}
   localCA=filepath.Join(installRoot,"ca.pem")
   if err:=atomicFile(localCA,b,0600);err!=nil{return err}
   if err:=os.Chown(localCA,int(uid),int(gid));err!=nil{return err}
  }
  if err:=os.Chown(installRoot,int(uid),int(gid));err!=nil{return err}
  if err:=invokeAs(uid,gid,bootstrap,[]string{"service","provision","--server",endpoint,"--ca-file",localCA},secret);err!=nil{return err}
  // The deferred rollback may restore legacy files only before a launch.
  if err:=atomicFile(unitPath,[]byte(unitText),0644);err!=nil{return err}
  if err:=systemctl("daemon-reload");err!=nil{return err}
  _=systemctl("reset-failed",serviceName)
  launched=true
  if err:=systemctl("start",serviceName);err!=nil{return errors.New("Agent did not become ready; inspect journalctl -u nezha-agent")}
  if err:=systemctl("enable",serviceName);err!=nil{return err}
  fmt.Println("Nezha Agent",version,"installed and running as",serviceName)
  return nil
 }
 if !bytes.Equal(oldUnit,[]byte(unitText)){if err:=atomicFile(unitPath,[]byte(unitText),0644);err!=nil{return err}}
 if err:=systemctl("daemon-reload");err!=nil{return err}
 _=systemctl("reset-failed",serviceName)
 // Type=notify blocks systemctl start until fresh authenticated reports.
 if err:=systemctl("start",serviceName);err!=nil{return errors.New("Agent did not become ready; inspect journalctl -u nezha-agent")}
 if err:=systemctl("enable",serviceName);err!=nil{return err}
 fmt.Println("Nezha Agent",version,"installed and running as",serviceName)
 return nil
}

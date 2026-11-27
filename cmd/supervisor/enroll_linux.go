//go:build linux

package main

import (
 "context"
 "encoding/hex"
 "encoding/json"
 "errors"
 "os"
 "path/filepath"
 "os/exec"
 "strings"
 "time"

 "github.com/onecat/nezha-agent/internal/config"
 "github.com/onecat/nezha-agent/internal/dashboard"
 "github.com/onecat/nezha-agent/internal/upgradestate"
)

// Enrollment is explicit and only possible for a new private installation.
// The existing certificate-verified Dashboard endpoint supplies its public
// key and the authenticated server ID; the local config pins that key.
func enrollLocal(path,agentPath,root string)error{
 for _,p:=range []string{path,agentPath,root}{if !filepath.IsAbs(p){return errors.New("absolute paths required")}}
 if _,err:=os.Lstat(path);!errors.Is(err,os.ErrNotExist){return errors.New("supervisor configuration already exists or inaccessible")}
 for _,p:=range []string{root,filepath.Join(root,"install"),filepath.Join(root,"state"),filepath.Join(root,"stage"),filepath.Dir(path)}{
  st,err:=os.Lstat(p);if err!=nil||!st.IsDir()||st.Mode().Perm()&0077!=0{return errors.New("private directories required")}
 }
 entries,err:=os.ReadDir(filepath.Join(root,"state"));if err!=nil||len(entries)!=0{return errors.New("state directory must be empty; never reset an existing ledger")}
 agent,err:=config.Load(agentPath);if err!=nil{return err}
 roots,err:=config.Roots(agent.CAFile);if err!=nil{return err}
 client,err:=dashboard.New(dashboard.Config{Address:agent.Address,Secret:agent.Secret,RootCAs:roots});if err!=nil{return err};defer client.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
 binary:=filepath.Join(root,"install","nezha-agent")
 st,err:=os.Lstat(binary);if err!=nil||!st.Mode().IsRegular()||st.Mode().Perm()&0077!=0{return errors.New("private installed Agent required")}
 out,err:=exec.CommandContext(ctx,binary,"--version").Output();if err!=nil{return errors.New("cannot read installed Agent version")}
 version:=strings.TrimSpace(string(out))
 if version!="v0.30.02"&&version!="v0.30.01"&&version!="v0.30.00"{return errors.New("unsupported initial Agent version")}
 info,err:=client.EnrollUpgrade(ctx);if err!=nil{return err}
 cfg:=settings{Enabled:true,ServerID:info.ServerID,InitialSequence:1,InitialVersion:version,AgentConfig:agentPath,InstallDir:filepath.Join(root,"install"),StateDir:filepath.Join(root,"state"),StageDir:filepath.Join(root,"stage"),Keys:map[string]string{"dashboard-local":hex.EncodeToString(info.Key)}}
 // Persist the pinned key before initializing. On a partial failure, stop
 // and require local review rather than silently replacing either file.
 data,err:=json.MarshalIndent(cfg,"","  ");if err!=nil{return err}
 f,err:=os.OpenFile(path,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600);if err!=nil{return err}
 if _,err=f.Write(data);err==nil{err=f.Sync()};closeErr:=f.Close();if err!=nil{return err};if closeErr!=nil{return closeErr}
 dir,err:=os.Open(filepath.Dir(path));if err!=nil{return err};err=dir.Sync();dir.Close();if err!=nil{return err}
 ledger,err:=upgradestate.InitializeVersion(cfg.StateDir,cfg.ServerID,cfg.InitialSequence,cfg.InitialVersion);if err!=nil{return err}
 return ledger.Close()
}

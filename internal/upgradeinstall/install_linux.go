//go:build linux

// Package upgradeinstall implements the local file replacement boundary only.
// It is not a network handler or a service supervisor.
package upgradeinstall

import (
 "archive/zip"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "runtime"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 "github.com/onecat/nezha-agent/internal/upgradestate"
 "golang.org/x/sys/unix"
)

const executable="nezha-agent"

// Installer requires an exclusive local state Store and an operator-owned
// executable directory whose ancestors cannot be modified by other users.
// The supervisor must serialize all calls and stop the worker before swapping.
type Installer struct {
 dir string
 state *upgradestate.Store
}

func New(dir string,state *upgradestate.Store)(*Installer,error){
 if state==nil||!filepath.IsAbs(dir){return nil,errors.New("invalid installer configuration")}
 st,err:=os.Lstat(dir)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0022!=0{return nil,errors.New("untrusted executable directory")}
 var stat unix.Stat_t
 if err:=unix.Lstat(dir,&stat);err!=nil||stat.Uid!=uint32(os.Geteuid()){return nil,errors.New("invalid directory ownership")}
 return &Installer{dir:dir,state:state},nil
}

func openExecutable(path string)(*os.File,os.FileInfo,error){
 fd,err:=unix.Open(path,unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,0)
 if err!=nil{return nil,nil,err}
 f:=os.NewFile(uintptr(fd),path)
 st,err:=f.Stat()
 if err!=nil||!st.Mode().IsRegular()||st.Mode().Perm()&0022!=0||
  st.Mode().Perm()&0100==0||st.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky)!=0||
  st.Size()<=0||st.Size()>core.MaxPackageSize{
  f.Close();return nil,nil,errors.New("invalid executable file")
 }
 var stat unix.Stat_t
 if err:=unix.Fstat(fd,&stat);err!=nil||stat.Uid!=uint32(os.Geteuid()){
  f.Close();return nil,nil,errors.New("invalid executable ownership")
 }
 return f,st,nil
}

func syncDir(dir string)error{
 f,err:=os.Open(dir)
 if err!=nil{return err}
 defer f.Close()
 return f.Sync()
}

func(i *Installer) backup(t core.Transaction)string{
 return filepath.Join(i.dir,fmt.Sprintf(".agent-backup-%d-%s",t.ReleaseSequence,t.PackageSHA256))
}
func(i *Installer) current(t core.Transaction)error{
 _,old,err:=i.state.Snapshot()
 if err!=nil{return err}
 if old==nil||!old.SameIdentity(t)||old.State!=t.State||!old.ExpiresAt.Equal(t.ExpiresAt){
  return errors.New("stale installation task")
 }
 return nil
}

// candidate extracts only the verified executable entry into a newly created
// local file. It verifies the extracted bytes again; no archive path is used.
func(i *Installer) candidate(r io.ReaderAt,size int64,p core.VerifiedPackage)(path string,err error){
 z,err:=zip.NewReader(r,size)
 if err!=nil{return "",err}
 var entry *zip.File
 for _,f:=range z.File{
  if f.Name==executable{
   if entry!=nil{return "",errors.New("duplicate executable")}
   entry=f
  }
 }
 if entry==nil{return "",errors.New("missing executable")}
 in,err:=entry.Open()
 if err!=nil{return "",err}
 defer in.Close()
 f,err:=os.CreateTemp(i.dir,".agent-candidate-")
 if err!=nil{return "",err}
 name:=f.Name()
 defer func(){f.Close();if err!=nil{os.Remove(name)}}()
 h:=sha256.New()
 n,err:=io.Copy(io.MultiWriter(f,h),io.LimitReader(in,p.Manifest.Size+1))
 if err!=nil{return "",err}
 if n!=p.Manifest.Size||hex.EncodeToString(h.Sum(nil))!=p.Manifest.SHA256{return "",errors.New("executable digest mismatch")}
 if err=f.Chmod(0700);err!=nil{return "",err}
 if err=f.Sync();err!=nil{return "",err}
 if err=f.Close();err!=nil{return "",err}
 return name,nil
}

// Install requires a previously reserved verified task and stable private
// archive bytes. It re-verifies trust, exact task identity and platform before
// creating a candidate. The old binary is backed up and directory-synced
// BEFORE the installing state is durably committed. Once installing is
// committed, any error requires recovery; never retry the swap blindly.
func(i *Installer) Install(t core.Transaction,r io.ReaderAt,size int64,keys map[string]ed25519.PublicKey,now time.Time)(core.Transaction,error){
 var zero core.Transaction
 if t.State!=core.StateVerified||now.IsZero()||!now.Before(t.ExpiresAt)||r==nil{return zero,errors.New("invalid installation task")}
 if err:=i.current(t);err!=nil{return zero,err}
 p,err:=core.VerifyPackage(r,size,keys)
 if err!=nil{return zero,err}
 if p.Manifest.OS!="linux"||p.Manifest.Arch!=runtime.GOARCH||
  !t.SameIdentity(core.Transaction{ID:t.ID,ServerID:t.ServerID,PackageSHA256:p.PackageSHA256,Version:p.Manifest.Version,ReleaseSequence:p.Manifest.ReleaseSequence}){
  return zero,errors.New("installation package mismatch")
 }
 target:=filepath.Join(i.dir,executable)
 old,oldInfo,err:=openExecutable(target)
 if err!=nil{return zero,err}
 defer old.Close()
 if err:=old.Sync();err!=nil{return zero,err}
 candidate,err:=i.candidate(r,size,p)
 if err!=nil{return zero,err}
 defer os.Remove(candidate)
 backup:=i.backup(t)
 // Never replace an existing backup. A pre-install orphan requires explicit
 // operator reconciliation; do not assume it belongs to the current worker.
 if err:=os.Link(target,backup);err!=nil{return zero,err}
 bf,bi,err:=openExecutable(backup)
 if err!=nil{return zero,err}
 bf.Close()
 if !os.SameFile(oldInfo,bi){return zero,errors.New("backup identity changed")}
 if err:=syncDir(i.dir);err!=nil{return zero,err}
 installing,err:=i.state.Advance(t,core.StateInstalling,time.Now())
 if err!=nil{return zero,err}
 // On any error after this point, preserve the backup and ledger.
 current,err:=os.Lstat(target)
 if err!=nil||!os.SameFile(oldInfo,current){return installing,errors.New("target identity changed")}
 if err:=os.Rename(candidate,target);err!=nil{return installing,err}
 if err:=syncDir(i.dir);err!=nil{return installing,err}
 return i.state.Advance(installing,core.StateHealthCheck,time.Now())
}

// Restore atomically restores the backed-up inode. It is restart-idempotent:
// the backup is retained even after restoration, and an interrupted rolling
// back state can be retried. Only the supervisor may later mark RolledBack
// after actually restarting and checking the restored worker.
func(i *Installer) Restore(t core.Transaction,now time.Time)(core.Transaction,error){
 var zero core.Transaction
 if now.IsZero(){return zero,errors.New("missing recovery time")}
 if err:=i.current(t);err!=nil{return zero,err}
 switch t.State{
 case core.StateInstalling,core.StateHealthCheck:
  next,err:=i.state.Advance(t,core.StateRollingBack,now)
  if err!=nil{return zero,err}
  t=next
 case core.StateRollingBack:
 default:return zero,errors.New("rollback not permitted")
 }
 backup:=i.backup(t)
 old,info,err:=openExecutable(backup)
 if err!=nil{return t,err}
 defer old.Close()
 // If already restored after a crash, sync and return the pending state.
 target:=filepath.Join(i.dir,executable)
 if cur,err:=os.Lstat(target);err==nil&&os.SameFile(info,cur){
  return t,syncDir(i.dir)
 }
 tmp,err:=os.CreateTemp(i.dir,".agent-restore-")
 if err!=nil{return t,err}
 path:=tmp.Name()
 defer os.Remove(path)
 if err:=tmp.Close();err!=nil{return t,err}
 // Copy the backup into the private candidate; the original stays available.
 // No untrusted path or executable arguments enter the restore operation.
 out,err:=os.OpenFile(path,os.O_WRONLY|os.O_TRUNC,0600)
 if err!=nil{return t,err}
 n,copyErr:=io.Copy(out,io.LimitReader(old,info.Size()+1))
 if copyErr==nil&&n!=info.Size(){copyErr=io.ErrUnexpectedEOF}
 if copyErr==nil{copyErr=out.Chmod(info.Mode().Perm())}
 if copyErr==nil{copyErr=out.Sync()}
 closeErr:=out.Close()
 if copyErr!=nil||closeErr!=nil{return t,errors.Join(copyErr,closeErr)}
 if err:=os.Rename(path,target);err!=nil{return t,err}
 return t,syncDir(i.dir)
}

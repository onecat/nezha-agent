// Package upgradestage receives a signed package into a private local file.
// It does not execute the binary or authorize a remote task.
package upgradestage

import (
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "runtime"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)

// Stage is single-owner and not concurrent safe. Caller must authenticate
// each transport message and enforce a single active task before creation.
// The directory and ancestors must be controlled by the local service account.
type Stage struct {
 task core.Transaction
 file *os.File
 path string
 size int64
 receiver *core.Receiver
 sealed bool
 closed bool
}

func New(dir string,t core.Transaction,size int64,now time.Time)(*Stage,error){
 if !filepath.IsAbs(dir)||now.IsZero()||!now.Before(t.ExpiresAt)||t.State!=core.StateTransferring{
  return nil,errors.New("invalid staging task or directory")
 }
 if _,err:=core.RecoveryDecision(t,now);err!=nil{return nil,err}
 st,err:=os.Lstat(dir)
 if err!=nil||!st.IsDir()||(runtime.GOOS!="windows"&&st.Mode().Perm()&0077!=0){
  return nil,errors.New("staging directory must be private")
 }
 f,err:=os.CreateTemp(dir,".upgrade-package-")
 if err!=nil{return nil,err}
 r,err:=core.NewReceiver(t.ID,t.ServerID,t.PackageSHA256,size,f)
 if err!=nil{f.Close();os.Remove(f.Name());return nil,err}
 return &Stage{task:t,file:f,path:f.Name(),size:size,receiver:r},nil
}

func(s *Stage) WriteChunk(c core.Chunk,now time.Time)error{
 if s.closed||s.sealed{return errors.New("stage is unavailable")}
 if now.IsZero()||!now.Before(s.task.ExpiresAt){s.Close();return errors.New("expired transfer")}
 if err:=s.receiver.WriteChunk(c);err!=nil{s.Close();return err}
 return nil
}

// Seal checks complete transfer, signature, package identity, platform,
// forward version and sequence. It closes the writable descriptor and
// reopens the same file read-only. The verified descriptor remains owned by
// Stage; callers must not use it after Close. The private directory is
// required; privileged local modification is outside the threat model.
func(s *Stage) Seal(keys map[string]ed25519.PublicKey,osName,arch,currentVersion string,highest uint64,now time.Time)(core.VerifiedPackage,error){
 var zero core.VerifiedPackage
 if s.closed||s.sealed{return zero,errors.New("stage is unavailable")}
 fail:=func(err error)(core.VerifiedPackage,error){s.Close();return zero,err}
 if now.IsZero()||!now.Before(s.task.ExpiresAt){return fail(errors.New("expired transfer"))}
 if err:=s.receiver.Finish();err!=nil{return fail(err)}
 if err:=s.file.Sync();err!=nil{return fail(err)}
 before,err:=s.file.Stat()
 if err!=nil||before.Size()!=s.size{return fail(errors.New("staging file size mismatch"))}
 if err:=s.file.Close();err!=nil{return fail(err)}
 s.file=nil
 f,err:=os.Open(s.path)
 if err!=nil{return fail(err)}
 s.file=f
 after,err:=f.Stat()
 if err!=nil||!os.SameFile(before,after)||after.Size()!=s.size{return fail(errors.New("staging file changed"))}
 p,err:=core.VerifyPackage(f,s.size,keys)
 if err!=nil{return fail(err)}
 if !s.task.SameIdentity(core.Transaction{ID:s.task.ID,ServerID:s.task.ServerID,PackageSHA256:p.PackageSHA256,Version:p.Manifest.Version,ReleaseSequence:p.Manifest.ReleaseSequence}){
  return fail(errors.New("package identity mismatch"))
 }
 if err:=p.Manifest.CheckUpgrade(osName,arch,currentVersion,highest);err!=nil{return fail(err)}
 s.sealed=true
 return p,nil
}

// ReadAt exposes only verified bytes. It does not provide a filesystem path
// for execution or a writable descriptor.
func(s *Stage) ReadAt(p []byte,off int64)(int,error){
 if s.closed||!s.sealed{return 0,errors.New("package is not verified")}
 return s.file.ReadAt(p,off)
}
func(s *Stage) Close()error{
 if s.closed{return nil}
 s.closed=true
 var err error
 if s.file!=nil{err=s.file.Close();s.file=nil}
 removeErr:=os.Remove(s.path)
 if errors.Is(removeErr,os.ErrNotExist){removeErr=nil}
 return errors.Join(err,removeErr)
}

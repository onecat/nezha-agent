//go:build linux

// Package upgradestate owns the local Linux supervisor's durable anti-rollback
// state. A private, operator-controlled, local filesystem is required.
package upgradestate

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "regexp"
 "sync"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 "golang.org/x/sys/unix"
)

const stateName="upgrade-state.json"
const lockName="upgrade-state.lock"
const maxState=8192

type record struct {
 Schema uint32 `json:"schema"`
 ServerID uint64 `json:"server_id"`
 Highest uint64 `json:"highest_sequence"`
 Task []byte `json:"task_snapshot"`
 CurrentVersion string `json:"current_version"`
 PreviousVersion string `json:"previous_version"`
 ResultReported bool `json:"result_reported"`
}

type Store struct{
 mu sync.Mutex
 dir string
 lock *os.File
 r record
 poisoned bool
}

func privateDir(dir string)error{
 if !filepath.IsAbs(dir){return errors.New("upgrade state requires absolute directory")}
 st,err:=os.Lstat(dir)
 if err!=nil||!st.IsDir()||st.Mode().Perm()&0077!=0{return errors.New("upgrade state requires existing private directory")}
 return nil
}

func openPrivate(path string,flags int)(*os.File,error){
 fd,err:=unix.Open(path,flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK,0600)
 if err!=nil{return nil,err}
 f:=os.NewFile(uintptr(fd),path)
 st,err:=f.Stat()
 if err!=nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077!=0{
  f.Close();return nil,errors.New("upgrade state is not a private regular file")
 }
 var info unix.Stat_t
 if err:=unix.Fstat(fd,&info);err!=nil||info.Uid!=uint32(os.Geteuid())||info.Nlink!=1{
  f.Close();return nil,errors.New("invalid upgrade state file ownership")
 }
 return f,nil
}

func acquire(dir string,initialize bool)(*Store,error){
 if err:=privateDir(dir);err!=nil{return nil,err}
 flags:=unix.O_RDWR
 if initialize {flags|=unix.O_CREAT|unix.O_EXCL}
 f,err:=openPrivate(filepath.Join(dir,lockName),flags)
 if err!=nil{return nil,err}
 if err:=unix.Flock(int(f.Fd()),unix.LOCK_EX|unix.LOCK_NB);err!=nil{f.Close();return nil,errors.New("upgrade state already in use")}
 return &Store{dir:dir,lock:f},nil
}

// Initialize is an explicit one-time provisioning operation. It never resets
// an existing ledger. An interrupted initialization must be investigated,
// not automatically retried with a lower sequence.
var releaseVersion=regexp.MustCompile(`^v[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}$`)

func Initialize(dir string,serverID,installedSequence uint64)(*Store,error){
 return InitializeVersion(dir,serverID,installedSequence,"v0.30.00")
}
func InitializeVersion(dir string,serverID,installedSequence uint64,version string)(*Store,error){
 if !releaseVersion.MatchString(version){return nil,errors.New("invalid initial version")}
 if serverID==0||installedSequence==0{return nil,errors.New("invalid initial identity or sequence")}
 s,err:=acquire(dir,true)
 if err!=nil{return nil,err}
 if _,err:=os.Lstat(filepath.Join(dir,stateName));!errors.Is(err,os.ErrNotExist){
  s.Close();return nil,errors.New("state already exists or cannot be checked")
 }
 if err:=s.lock.Sync();err!=nil{s.Close();return nil,err}
 r:=record{Schema:2,ServerID:serverID,Highest:installedSequence,CurrentVersion:version}
 if err:=s.persist(r);err!=nil{s.Close();return nil,err}
 return s,nil
}

// Open never creates missing state. The provisioned identity must match.
func Open(dir string,serverID uint64)(*Store,error){
 if serverID==0{return nil,errors.New("invalid server identity")}
 s,err:=acquire(dir,false)
 if err!=nil{return nil,err}
 f,err:=openPrivate(filepath.Join(dir,stateName),unix.O_RDONLY)
 if err!=nil{s.Close();return nil,err}
 b,err:=io.ReadAll(io.LimitReader(f,maxState+1))
 f.Close()
 if err!=nil||len(b)>maxState{s.Close();return nil,errors.New("invalid state size")}
 r,err:=decode(b)
 if err!=nil||r.ServerID!=serverID{s.Close();return nil,errors.New("invalid state or server identity")}
 s.r=r
 return s,nil
}

func decode(b []byte)(record,error){
 var r record
 if err:=json.Unmarshal(b,&r);err!=nil{return r,err}
 // Canonical exact encoding rejects duplicate, missing, unknown, null
 // scalar fields, alternate spellings and trailing input.
 canonical,err:=json.Marshal(r)
 if err!=nil||!bytes.Equal(b,canonical)||r.Schema!=2||r.ServerID==0||r.Highest==0||!releaseVersion.MatchString(r.CurrentVersion){
  return r,errors.New("invalid ledger encoding")
 }
 if r.Task!=nil{
  t,err:=core.DecodeSnapshot(r.Task)
  if err!=nil||t.ServerID!=r.ServerID||t.ReleaseSequence!=r.Highest||
   t.State==core.StatePending||t.State==core.StateTransferring{
   return r,errors.New("invalid ledger task")
  }
  if !releaseVersion.MatchString(r.PreviousVersion)||(r.ResultReported&&!terminal(t.State))||
   (t.State==core.StateSucceeded&&r.CurrentVersion!=t.Version)||
   (t.State!=core.StateSucceeded&&r.CurrentVersion!=r.PreviousVersion){return r,errors.New("invalid ledger version or receipt")}
 }else if r.PreviousVersion!=""||r.ResultReported{return r,errors.New("unexpected ledger metadata")}
 return r,nil
}

// persist writes, syncs and atomically replaces the record, then syncs the
// directory. Any ambiguous error poisons the handle; caller must stop and
// reopen to determine durable state before further side effects.
func(s *Store)persist(r record)(err error){
 defer func(){if err!=nil{s.poisoned=true}}()
 b,err:=json.Marshal(r)
 if err!=nil{return err}
 if len(b)>maxState{return errors.New("upgrade state too large")}
 if _,err:=decode(b);err!=nil{return err}
 f,err:=os.CreateTemp(s.dir,".upgrade-state-")
 if err!=nil{return err}
 defer os.Remove(f.Name())
 defer f.Close()
 if n,err:=f.Write(b);err!=nil{return err}else if n!=len(b){return io.ErrShortWrite}
 if err:=f.Sync();err!=nil{return err}
 if err:=f.Close();err!=nil{return err}
 if err:=os.Rename(f.Name(),filepath.Join(s.dir,stateName));err!=nil{return err}
 d,err:=os.Open(s.dir)
 if err!=nil{return err}
 defer d.Close()
 if err:=d.Sync();err!=nil{return err}
 s.r=r
 return nil
}

func(s *Store)ready()error{
 if s.lock==nil||s.poisoned{return errors.New("upgrade state unavailable; reopen required")}
 return nil
}
func(s *Store) Snapshot()(uint64,*core.Transaction,error){
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.ready();err!=nil{return 0,nil,err}
 if s.r.Task==nil{return s.r.Highest,nil,nil}
 t,err:=core.DecodeSnapshot(s.r.Task)
 if err!=nil{return 0,nil,err}
 return s.r.Highest,&t,nil
}
func terminal(st core.State)bool{return st==core.StateSucceeded||st==core.StateRolledBack||st==core.StateFailed}

// ReserveVerified consumes a signed release sequence BEFORE installation.
// Caller must authenticate the task, bind the immutable staged bytes and
// independently verify the package with provisioned trusted keys. This
// method checks the verified metadata, not the trust provenance.
func(s *Store)ReserveVerified(t core.Transaction,p core.VerifiedPackage,osName,arch,currentVersion string,now time.Time)error{
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.ready();err!=nil{return err}
 if s.r.Task!=nil{
  old,err:=core.DecodeSnapshot(s.r.Task)
  if err!=nil{return err}
  if !terminal(old.State)||!s.r.ResultReported||old.ID==t.ID{return errors.New("active or repeated upgrade task")}
 }
 if t.ServerID!=s.r.ServerID||t.State!=core.StateVerified||now.IsZero()||!now.Before(t.ExpiresAt)||
  !t.SameIdentity(core.Transaction{ID:t.ID,ServerID:s.r.ServerID,PackageSHA256:p.PackageSHA256,Version:p.Manifest.Version,ReleaseSequence:p.Manifest.ReleaseSequence}){
  return errors.New("invalid verified task identity")
 }
 if currentVersion!=s.r.CurrentVersion{return errors.New("installed version mismatch")}
 if err:=p.Manifest.CheckUpgrade(osName,arch,currentVersion,s.r.Highest);err!=nil{return err}
 b,err:=core.EncodeSnapshot(t)
 if err!=nil{return err}
 r:=s.r;r.Highest=t.ReleaseSequence;r.Task=b;r.PreviousVersion=currentVersion;r.ResultReported=false
 return s.persist(r)
}

// Advance uses the expected identity, state and expiry as a CAS predicate.
// Caller is responsible for actual installation/health/rollback evidence.
// Never reduces the consumed release sequence, including after rollback.
func(s *Store)Advance(expected core.Transaction,next core.State,now time.Time)(core.Transaction,error){
 s.mu.Lock();defer s.mu.Unlock()
 var zero core.Transaction
 if err:=s.ready();err!=nil{return zero,err}
 if s.r.Task==nil{return zero,errors.New("no active task")}
 t,err:=core.DecodeSnapshot(s.r.Task)
 if err!=nil{return zero,err}
 if !t.SameIdentity(expected)||t.State!=expected.State||!t.ExpiresAt.Equal(expected.ExpiresAt){return zero,errors.New("stale task state")}
 t,err=t.Transition(next,now)
 if err!=nil{return zero,err}
 b,err:=core.EncodeSnapshot(t)
 if err!=nil{return zero,err}
 r:=s.r;r.Task=b
 if next==core.StateSucceeded{r.CurrentVersion=t.Version}
 if err:=s.persist(r);err!=nil{return zero,err}
 return t,nil
}
func(s *Store)Close()error{
 s.mu.Lock();defer s.mu.Unlock()
 if s.lock==nil{return nil}
 err:=s.lock.Close()
 s.lock=nil
 return err
}

 // VersionInfo returns trusted local metadata from the same durable record
 // as the task and sequence.
func(s *Store) VersionInfo()(current,previous string,reported bool,err error){
 s.mu.Lock();defer s.mu.Unlock()
 if err=s.ready();err!=nil{return}
 return s.r.CurrentVersion,s.r.PreviousVersion,s.r.ResultReported,nil
}
// MarkReported is called only after the exact terminal receipt is acknowledged
// by the authenticated Dashboard. Until then no new task may replace it.
func(s *Store) MarkReported(expected core.Transaction)error{
 s.mu.Lock();defer s.mu.Unlock()
 if err:=s.ready();err!=nil{return err}
 if s.r.Task==nil{return errors.New("no terminal task")}
 t,err:=core.DecodeSnapshot(s.r.Task)
 if err!=nil{return err}
 if !terminal(t.State)||t.State!=expected.State||!t.SameIdentity(expected)||!t.ExpiresAt.Equal(expected.ExpiresAt){return errors.New("receipt identity mismatch")}
 if s.r.ResultReported{return nil}
 r:=s.r;r.ResultReported=true
 return s.persist(r)
}

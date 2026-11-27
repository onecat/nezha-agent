//go:build linux

// Package worker manages a local Agent child process. No network-provided
// commands, paths, arguments or environment variables are accepted.
package worker

import (
 "context"
 "errors"
 "io"
 "os"
 "os/exec"
 "path/filepath"
 "sync"
 "syscall"
 "time"
)

type Process struct{
 mu sync.Mutex
 executable,config string
 cmd *exec.Cmd
 done chan struct{}
 life *os.File
 ready chan readyResult
 proof *readyResult
}
type readyResult struct{value string;err error}

// New is configured by a trusted local operator. The executable directory
// and configuration must remain protected against untrusted modification.
func New(dir,config string)(*Process,error){
 if !filepath.IsAbs(dir)||!filepath.IsAbs(config){return nil,errors.New("worker paths must be absolute")}
 return &Process{executable:filepath.Join(dir,"nezha-agent"),config:config},nil
}

func(p *Process) Start(ctx context.Context)error{
 p.mu.Lock();defer p.mu.Unlock()
 if err:=ctx.Err();err!=nil{return err}
 if p.cmd!=nil{return errors.New("previous worker must be stopped and reaped")}
 rr,rw,err:=os.Pipe()
 if err!=nil{return err}
 lr,lw,err:=os.Pipe()
 if err!=nil{rr.Close();rw.Close();return err}
 defer rw.Close()
 defer lr.Close()
 cmd:=exec.Command(p.executable,"--config",p.config,"--supervised")
 cmd.Dir=filepath.Dir(p.executable)
 cmd.ExtraFiles=[]*os.File{rw,lr}
 cmd.Stdout=io.Discard
 cmd.Stderr=os.Stderr
 if err:=cmd.Start();err!=nil{rr.Close();lw.Close();return err}
 p.cmd=cmd
 p.done=make(chan struct{})
 p.life=lw
 p.ready=make(chan readyResult,1)
 p.proof=nil
 done,ready:=p.done,p.ready
 go func(){_ =cmd.Wait();close(done)}()
 go func(){
  defer rr.Close()
  b,err:=io.ReadAll(io.LimitReader(rr,65))
  if err==nil&&len(b)>64{err=errors.New("oversized readiness response")}
  ready<-readyResult{string(b),err}
 }()
 return nil
}

// Healthy consumes the one-shot proof from this specific launch, then checks
// the worker remains alive through a short stabilization period. It is not
// ongoing liveness monitoring and does not trust an old Dashboard heartbeat.
func(p *Process) Healthy(ctx context.Context,version string)error{
 p.mu.Lock();defer p.mu.Unlock()
 if p.cmd==nil||version==""{return errors.New("no active worker or version")}
 if p.proof==nil{
  select{
  case <-ctx.Done():return ctx.Err()
  case <-p.done:return errors.New("worker exited before readiness")
  case v:=<-p.ready:p.proof=&v
  }
 }
 if p.proof.err!=nil||p.proof.value!=version+"\n"{return errors.New("worker readiness mismatch")}
 timer:=time.NewTimer(500*time.Millisecond)
 defer timer.Stop()
 select{
 case <-ctx.Done():return ctx.Err()
 case <-p.done:return errors.New("worker exited during readiness")
 case <-timer.C:
 }
 select{case <-p.done:return errors.New("worker exited");default:return ctx.Err()}
}

// Stop confirms the child has been reaped before permitting another Start.
// Closing the private life pipe and SIGTERM request a graceful exit; a
// bounded grace period escalates to killing this exact child.
func(p *Process) Stop(ctx context.Context)error{
 p.mu.Lock();defer p.mu.Unlock()
 if p.cmd==nil{return nil}
 if p.life!=nil{p.life.Close();p.life=nil}
 clear:=func(){p.cmd=nil;p.done=nil;p.ready=nil;p.proof=nil}
 select{case <-p.done:clear();return nil;default:}
 _=p.cmd.Process.Signal(syscall.SIGTERM)
 timer:=time.NewTimer(2*time.Second)
 defer timer.Stop()
 select{
 case <-p.done:clear();return nil
 case <-ctx.Done():
  _=p.cmd.Process.Kill()
  return ctx.Err()
 case <-timer.C:
  _=p.cmd.Process.Kill()
 }
 select{
 case <-p.done:clear();return nil
 case <-ctx.Done():return ctx.Err()
 }
}

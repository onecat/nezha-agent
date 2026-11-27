//go:build linux

package main

import (
 "context"
 "errors"
 "io"
 "os"
 "sync"
)

// The inherited anonymous pipes are private to this worker and its parent.
// fd 3 sends readiness only after both authenticated reports are accepted.
// fd 4 is held open by the parent; EOF requests shutdown.
func supervisorPipes(ctx context.Context,stop context.CancelFunc,enabled bool)(func()error,func(),error){
 noop:=func(){}
 if !enabled{return nil,noop,nil}
 ready:=os.NewFile(3,"worker-readiness")
 life:=os.NewFile(4,"supervisor-lifetime")
 if ready==nil||life==nil{return nil,noop,errors.New("missing supervisor pipes")}
 closeAll:=func(){ready.Close();life.Close()}
 for _,f:=range []*os.File{ready,life}{
  st,err:=f.Stat()
  if err!=nil||st.Mode()&os.ModeNamedPipe==0{closeAll();return nil,noop,errors.New("invalid supervisor pipe")}
 }
 go func(){
  var b [1]byte
  // The parent never writes data. Any byte, EOF or error terminates the worker.
  _,_=life.Read(b[:])
  stop()
 }()
 var once sync.Once
 var result error
 notify:=func()error{
  once.Do(func(){
   if ctx.Err()!=nil{result=ctx.Err();return}
   n,err:=io.WriteString(ready,version+"\n")
   if err==nil&&n!=len(version)+1{err=io.ErrShortWrite}
   result=errors.Join(err,ready.Close())
  })
  return result
 }
 return notify,closeAll,nil
}

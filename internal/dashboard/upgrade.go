package dashboard

import (
 "context"
 "crypto/ed25519"
 "errors"
 "io"
 "time"

 "github.com/onecat/nezha-agent/internal/upgradestage"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 wire "github.com/onecat/nezha-agent/pkg/upgradewire"
 "google.golang.org/protobuf/types/known/wrapperspb"
)

// DownloadedUpgrade owns a sealed private package. Close must be called.
// Verification acknowledgement is NOT permission to install.
type DownloadedUpgrade struct{
 task core.Transaction
 verified core.VerifiedPackage
 size int64
 stage *upgradestage.Stage
 owner *Client
}
func(d *DownloadedUpgrade) Task()core.Transaction{return d.task}
func(d *DownloadedUpgrade) Package()core.VerifiedPackage{return d.verified}
func(d *DownloadedUpgrade) Size()int64{return d.size}
func(d *DownloadedUpgrade) ReadAt(b []byte,offset int64)(int,error){
 if d.stage==nil{return 0,errors.New("download closed")}
 return d.stage.ReadAt(b,offset)
}
func(d *DownloadedUpgrade) Close()error{
 if d.stage==nil{return nil}
 err:=d.stage.Close();d.stage=nil;return err
}

// DownloadUpgrade uses the existing certificate-validated TLS connection.
// Expected identity and high-water mark must be provisioned from trusted
// local state, not the incoming header. Caller serializes task handling.
// This method stages bytes only; it cannot replace the running Agent.
func(c *Client) DownloadUpgrade(ctx context.Context,dir string,serverID uint64,currentVersion,osName,arch string,highest uint64,keys map[string]ed25519.PublicKey)(*DownloadedUpgrade,error){
 if serverID==0||highest==0||osName!="linux"||(arch!="amd64"&&arch!="arm64")||len(keys)==0{return nil,errors.New("managed upgrade not provisioned")}
 ctx,cancel:=context.WithTimeout(ctx,wire.MaxDownloadTime)
 defer cancel()
 stream,err:=wire.Download(ctx,c.conn)
 if err!=nil{return nil,err}
 msg:=new(wrapperspb.BytesValue)
 if err:=stream.RecvMsg(msg);err!=nil{return nil,err}
 h,err:=wire.DecodeHeader(msg.Value)
 if err!=nil{return nil,err}
 if h.Task.ServerID!=serverID||h.Task.ReleaseSequence<=highest||!time.Now().Before(h.Task.ExpiresAt){
  return nil,errors.New("untrusted download identity, expiry or sequence")
 }
 stage,err:=upgradestage.New(dir,h.Task,h.Size,time.Now())
 if err!=nil{return nil,err}
 keep:=false
 defer func(){if !keep{stage.Close()}}()
 for{
  msg=new(wrapperspb.BytesValue)
  err:=stream.RecvMsg(msg)
  if err==io.EOF{break}
  if err!=nil{return nil,err}
  chunk,err:=wire.DecodeChunk(h,msg.Value)
  if err!=nil{return nil,err}
  if err:=stage.WriteChunk(chunk,time.Now());err!=nil{return nil,err}
 }
 p,err:=stage.Seal(keys,osName,arch,currentVersion,highest,time.Now())
 if err!=nil{return nil,err}
 t,err:=h.Task.Transition(core.StateVerified,time.Now())
 if err!=nil{return nil,err}
 if err:=ctx.Err();err!=nil{return nil,err}
 keep=true
 return &DownloadedUpgrade{task:t,verified:p,size:h.Size,stage:stage,owner:c},nil
}

// AcknowledgeVerified records the completed signature verification on the
// Dashboard. It does not consume a local sequence or authorize installation.
// The caller may retry this receipt while the exact task remains valid.
func(c *Client) AcknowledgeVerified(ctx context.Context,d *DownloadedUpgrade)error{
 if d==nil||d.stage==nil||d.owner!=c||d.task.State!=core.StateVerified||!time.Now().Before(d.task.ExpiresAt){return errors.New("invalid verified download")}
 ctx,cancel:=context.WithTimeout(ctx,rpcTimeout)
 defer cancel()
 return wire.Verify(ctx,c.conn,d.task)
}

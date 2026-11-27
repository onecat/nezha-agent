// Package upgradewire defines the bounded managed-upgrade v1 gRPC transport.
// Standard protobuf BytesValue envelopes avoid modifying legacy NezhaService.
package upgradewire

import (
 "context"
 "encoding/binary"
 "errors"
 "time"

 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
 "google.golang.org/grpc"
 "google.golang.org/protobuf/types/known/wrapperspb"
)

const Service="nezha.upgrade.v1.ManagedUpgrade"
const DownloadMethod="/"+Service+"/Download"
const VerifyMethod="/"+Service+"/Verify"
const MaxMessage=core.ChunkSize+1024
const MaxDownloadTime=2*time.Minute

type Header struct{Task core.Transaction;Size int64}
func EncodeHeader(h Header)([]byte,error){
 if h.Size<=0||h.Size>core.MaxPackageSize||h.Task.State!=core.StateTransferring{return nil,errors.New("invalid download header")}
 b,err:=core.EncodeSnapshot(h.Task)
 if err!=nil{return nil,err}
 out:=make([]byte,8+len(b))
 binary.BigEndian.PutUint64(out,uint64(h.Size))
 copy(out[8:],b)
 return out,nil
}
func DecodeHeader(b []byte)(Header,error){
 if len(b)<=8||len(b)>8+core.MaxSnapshotSize{return Header{},errors.New("invalid download header length")}
 n:=binary.BigEndian.Uint64(b[:8])
 if n==0||n>uint64(core.MaxPackageSize){return Header{},errors.New("invalid download size")}
 t,err:=core.DecodeSnapshot(b[8:])
 if err!=nil||t.State!=core.StateTransferring{return Header{},errors.New("invalid download task")}
 return Header{Task:t,Size:int64(n)},nil
}
func EncodeChunk(c core.Chunk)([]byte,error){
 if c.Offset<0||c.Offset>core.MaxPackageSize||len(c.Data)==0||len(c.Data)>core.ChunkSize{return nil,errors.New("invalid chunk")}
 out:=make([]byte,8+len(c.Data))
 binary.BigEndian.PutUint64(out,uint64(c.Offset))
 copy(out[8:],c.Data)
 return out,nil
}
func DecodeChunk(h Header,b []byte)(core.Chunk,error){
 if len(b)<=8||len(b)>8+core.ChunkSize{return core.Chunk{},errors.New("invalid chunk length")}
 off:=binary.BigEndian.Uint64(b[:8])
 if off>uint64(h.Size)||uint64(len(b)-8)>uint64(h.Size)-off{return core.Chunk{},errors.New("chunk out of bounds")}
 return core.Chunk{TaskID:h.Task.ID,ServerID:h.Task.ServerID,PackageSHA256:h.Task.PackageSHA256,Offset:int64(off),Data:b[8:]},nil
}

type Server interface{
 Download(*wrapperspb.BytesValue,grpc.ServerStream)error
 Verify(context.Context,*wrapperspb.BytesValue)(*wrapperspb.BytesValue,error)
}

func Register(s grpc.ServiceRegistrar,impl Server){
 s.RegisterService(&descriptor,impl)
}
var descriptor=grpc.ServiceDesc{
 ServiceName:Service,
 HandlerType:(*Server)(nil),
 Methods:[]grpc.MethodDesc{{MethodName:"Verify",Handler:verifyHandler}},
 Streams:[]grpc.StreamDesc{{StreamName:"Download",ServerStreams:true,Handler:downloadHandler}},
}
func downloadHandler(srv any,stream grpc.ServerStream)error{
 msg:=new(wrapperspb.BytesValue)
 if err:=stream.RecvMsg(msg);err!=nil{return err}
 return srv.(Server).Download(msg,stream)
}
func verifyHandler(srv any,ctx context.Context,decode func(any)error,interceptor grpc.UnaryServerInterceptor)(any,error){
 msg:=new(wrapperspb.BytesValue)
 if err:=decode(msg);err!=nil{return nil,err}
 if interceptor==nil{return srv.(Server).Verify(ctx,msg)}
 return interceptor(ctx,msg,&grpc.UnaryServerInfo{Server:srv,FullMethod:VerifyMethod},func(ctx context.Context,req any)(any,error){
  return srv.(Server).Verify(ctx,req.(*wrapperspb.BytesValue))
 })
}
func Download(ctx context.Context,c grpc.ClientConnInterface)(grpc.ClientStream,error){
 stream,err:=c.NewStream(ctx,&descriptor.Streams[0],DownloadMethod,grpc.MaxCallRecvMsgSize(MaxMessage),grpc.MaxCallSendMsgSize(MaxMessage))
 if err!=nil{return nil,err}
 if err:=stream.SendMsg(&wrapperspb.BytesValue{});err!=nil{return nil,err}
 if err:=stream.CloseSend();err!=nil{return nil,err}
 return stream,nil
}
func Verify(ctx context.Context,c grpc.ClientConnInterface,t core.Transaction)error{
 if t.State!=core.StateVerified{return errors.New("invalid verification state")}
 b,err:=core.EncodeSnapshot(t)
 if err!=nil{return err}
 out:=new(wrapperspb.BytesValue)
 if err:=c.Invoke(ctx,VerifyMethod,wrapperspb.Bytes(b),out,grpc.MaxCallRecvMsgSize(MaxMessage),grpc.MaxCallSendMsgSize(MaxMessage));err!=nil{return err}
 if string(out.Value)!="verified"{return errors.New("invalid verification acknowledgement")}
 return nil
}

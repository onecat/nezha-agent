package dashboard

import(
 "context"
 "encoding/binary"
 "errors"
 "crypto/ed25519"
 "runtime"
 "google.golang.org/protobuf/types/known/wrapperspb"
)
type Enrollment struct{ServerID uint64;Key ed25519.PublicKey}
func(c *Client)EnrollUpgrade(ctx context.Context)(Enrollment,error){
 var result Enrollment
 if runtime.GOOS!="linux"||runtime.GOARCH!="amd64"{return result,errors.New("URL enrollment currently supports Linux amd64")}
 out:=new(wrapperspb.BytesValue)
 ctx,cancel:=context.WithTimeout(ctx,rpcTimeout);defer cancel()
 if err:=c.conn.Invoke(ctx,"/nezha.upgrade.v1.ManagedUpgrade/Enroll",wrapperspb.Bytes([]byte("linux/amd64")),out);err!=nil{return result,err}
 if len(out.Value)!=8+ed25519.PublicKeySize{return result,errors.New("invalid enrollment response")}
 result.ServerID=binary.BigEndian.Uint64(out.Value[:8]);result.Key=append(ed25519.PublicKey(nil),out.Value[8:]...)
 if result.ServerID==0{return Enrollment{},errors.New("invalid enrolled identity")}
 return result,nil
}

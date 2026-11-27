package agentupgrade

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "io"
 "strings"
 "testing"
)

func TestReceiverComplete(t *testing.T) {
 data:=bytes.Repeat([]byte("x"),ChunkSize+5)
 sum:=sha256.Sum256(data)
 digest:=hex.EncodeToString(sum[:])
 var out bytes.Buffer
 r,err:=NewReceiver("task-1",7,digest,int64(len(data)),&out)
 if err!=nil {t.Fatal(err)}
 for _,c:=range []Chunk{
  {TaskID:"task-1",ServerID:7,PackageSHA256:digest,Offset:0,Data:data[:ChunkSize]},
  {TaskID:"task-1",ServerID:7,PackageSHA256:digest,Offset:ChunkSize,Data:data[ChunkSize:]},
 } {
  if err:=r.WriteChunk(c);err!=nil {t.Fatal(err)}
 }
 if err:=r.Finish();err!=nil {t.Fatal(err)}
 if !bytes.Equal(data,out.Bytes()) {t.Fatal("data mismatch")}
 if err:=r.Finish();err==nil {t.Fatal("accepted duplicate finish")}
}
func TestReceiverRejectsTampering(t *testing.T) {
 data:=[]byte("abcdef")
 sum:=sha256.Sum256(data)
 digest:=hex.EncodeToString(sum[:])
 base:=Chunk{TaskID:"t",ServerID:1,PackageSHA256:digest,Offset:0,Data:data}
 cases:=[]struct{name string;modify func(*Chunk)}{
  {"task",func(c *Chunk){c.TaskID="other"}},
  {"server",func(c *Chunk){c.ServerID=2}},
  {"digest",func(c *Chunk){c.PackageSHA256=strings.Repeat("0",64)}},
  {"offset",func(c *Chunk){c.Offset=1}},
  {"empty",func(c *Chunk){c.Data=nil}},
  {"oversized",func(c *Chunk){c.Data=make([]byte,ChunkSize+1)}},
  {"exceeds total",func(c *Chunk){c.Data=append([]byte(nil),data...);c.Data=append(c.Data,1)}},
 }
 for _,tc:=range cases {t.Run(tc.name,func(t *testing.T){
  r,err:=NewReceiver("t",1,digest,int64(len(data)),io.Discard)
  if err!=nil {t.Fatal(err)}
  c:=base;tc.modify(&c)
  if err:=r.WriteChunk(c);err==nil {t.Fatal("accepted invalid chunk")}
  if err:=r.WriteChunk(base);err==nil {t.Fatal("accepted reuse after failure")}
 })}
 r,_:=NewReceiver("t",1,digest,int64(len(data)),io.Discard)
 bad:=base;bad.Data=[]byte("ABCDEF")
 if err:=r.WriteChunk(bad);err!=nil {t.Fatal(err)}
 if err:=r.Finish();err==nil {t.Fatal("accepted tampered payload")}
 r,_=NewReceiver("t",1,digest,int64(len(data)),io.Discard)
 if err:=r.Finish();err==nil {t.Fatal("accepted incomplete transfer")}
}
type failingWriter struct{}
func (failingWriter) Write(p []byte)(int,error){return 0,errors.New("disk full")}
func TestReceiverWriterFailure(t *testing.T) {
 sum:=sha256.Sum256([]byte("a")); digest:=hex.EncodeToString(sum[:])
 r,_:=NewReceiver("t",1,digest,1,failingWriter{})
 c:=Chunk{TaskID:"t",ServerID:1,PackageSHA256:digest,Data:[]byte("a")}
 if err:=r.WriteChunk(c);err==nil {t.Fatal("ignored disk error")}
 if err:=r.WriteChunk(c);err==nil {t.Fatal("reused failed receiver")}
 for _,size:=range []int64{0,MaxPackageSize+1} {
  if _,err:=NewReceiver("t",1,digest,size,io.Discard);err==nil {t.Fatal("accepted invalid size")}
 }
}

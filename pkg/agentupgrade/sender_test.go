package agentupgrade

import (
 "bytes"
 "crypto/sha256"
 "encoding/hex"
 "io"
 "strings"
 "testing"
)

func TestSenderReceiverRoundTrip(t *testing.T) {
 data:=bytes.Repeat([]byte("safe offline fixture"),18000)
 sum:=sha256.Sum256(data)
 digest:=hex.EncodeToString(sum[:])
 tx:=Transaction{ID:"task-1",ServerID:9,PackageSHA256:digest,State:StateTransferring}
 sender,err:=NewSender(tx,bytes.NewReader(data),int64(len(data)))
 if err!=nil { t.Fatal(err) }
 var out bytes.Buffer
 recv,err:=NewReceiver(tx.ID,tx.ServerID,digest,int64(len(data)),&out)
 if err!=nil { t.Fatal(err) }
 for off:=int64(0);; {
  c,done,err:=sender.ChunkAt(off)
  if err!=nil { t.Fatal(err) }
  if done { break }
  if len(c.Data)==0 || len(c.Data)>ChunkSize { t.Fatal("bad chunk size") }
  if err:=recv.WriteChunk(c);err!=nil { t.Fatal(err) }
  off+=int64(len(c.Data))
 }
 if err:=recv.Finish();err!=nil { t.Fatal(err) }
 if !bytes.Equal(data,out.Bytes()) { t.Fatal("transfer bytes differ") }
 for _,off:=range []int64{-1,int64(len(data))+1} {
  if _,_,err:=sender.ChunkAt(off);err==nil { t.Fatal("invalid offset accepted") }
 }
 if _,done,err:=sender.ChunkAt(int64(len(data)));err!=nil || !done { t.Fatal("end offset not recognized") }
 if _,err:=NewSender(tx,bytes.NewReader([]byte("bad")),int64(len(data)));err==nil { t.Fatal("short source accepted") }
 if _,err:=NewSender(tx,bytes.NewReader(data),int64(len(data)-1));err==nil { t.Fatal("wrong digest accepted") }
 tx.State=StatePending
 if _,err:=NewSender(tx,bytes.NewReader(data),int64(len(data)));err==nil { t.Fatal("pending state accepted") }
}

type truncatedSource struct{}
func (truncatedSource) ReadAt(p []byte,off int64)(int,error) { return 0,io.EOF }
func TestSenderRejectsTruncatedSource(t *testing.T) {
 tx:=Transaction{ID:"x",ServerID:1,PackageSHA256:strings.Repeat("a",64),State:StateTransferring}
 if _,err:=NewSender(tx,truncatedSource{},123);err==nil { t.Fatal("truncated source accepted") }
}

package upgradewire

import (
 "bytes"
 "strings"
 "testing"
 "time"
 core "github.com/onecat/nezha-agent/pkg/agentupgrade"
)
func TestWireBounds(t *testing.T){
 tx:=core.Transaction{ID:"task",ServerID:1,PackageSHA256:strings.Repeat("a",64),Version:"v0.30.01",ReleaseSequence:2,State:core.StateTransferring,ExpiresAt:time.Now().Add(time.Minute)}
 h:=Header{Task:tx,Size:10}
 b,err:=EncodeHeader(h)
 if err!=nil{t.Fatal(err)}
 got,err:=DecodeHeader(b)
 if err!=nil||!got.Task.SameIdentity(tx)||got.Size!=10{t.Fatal("header mismatch",err)}
 c:=core.Chunk{Offset:7,Data:[]byte("abc")}
 b,err=EncodeChunk(c)
 if err!=nil{t.Fatal(err)}
 chunk,err:=DecodeChunk(got,b)
 if err!=nil||chunk.TaskID!=tx.ID||chunk.ServerID!=1||!bytes.Equal(chunk.Data,c.Data){t.Fatal("chunk mismatch",err)}
 if _,err:=DecodeChunk(Header{Task:tx,Size:9},b);err==nil{t.Fatal("out of bounds chunk")}
 if _,err:=DecodeHeader([]byte{1});err==nil{t.Fatal("short header accepted")}
 if _,err:=EncodeChunk(core.Chunk{Offset:-1,Data:[]byte("a")});err==nil{t.Fatal("negative offset")}
}

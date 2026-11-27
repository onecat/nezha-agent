package agentupgrade

import (
 "bytes"
 "strings"
 "testing"
 "time"
)

func TestSnapshotStrictRoundTrip(t *testing.T) {
 t0:=Transaction{ID:"task-1",ServerID:42,PackageSHA256:strings.Repeat("a",64),
  Version:"v0.30.01",ReleaseSequence:2,State:StateInstalling,
  ExpiresAt:time.Date(2030,1,2,3,4,5,0,time.UTC)}
 b,err:=EncodeSnapshot(t0)
 if err!=nil { t.Fatal(err) }
 out,err:=DecodeSnapshot(b)
 if err!=nil { t.Fatal(err) }
 if !out.SameIdentity(t0) || out.State!=t0.State || !out.ExpiresAt.Equal(t0.ExpiresAt) { t.Fatal("round trip mismatch") }
 cases:=[][]byte{
  append(append([]byte(nil),b...),[]byte(" trailing")...),
  bytes.Replace(b,[]byte(`"schema_version":1`),[]byte(`"schema_version":2`),1),
  bytes.Replace(b,[]byte(`"schema_version":1`),[]byte(`"schema_version":1,"schema_version":1`),1),
  bytes.Replace(b,[]byte(`"schema_version":1`),[]byte(`"unexpected":1,"schema_version":1`),1),
  bytes.Replace(b,[]byte(`"id":"task-1",`),nil,1),
  bytes.Replace(b,[]byte(`"id":"task-1"`),[]byte(`"id":null`),1),
  bytes.Replace(b,[]byte(`"state":"installing"`),[]byte(`"state":"unknown"`),1),
  bytes.Repeat([]byte("x"),MaxSnapshotSize+1),
 }
 for i,bad:=range cases { if _,err:=DecodeSnapshot(bad);err==nil { t.Errorf("accepted invalid snapshot %d",i) } }
}

func TestSnapshotRejectsInvalidTransaction(t *testing.T) {
 if _,err:=EncodeSnapshot(Transaction{});err==nil { t.Fatal("accepted empty transaction") }
}

package agentupgrade

import (
 "bytes"
 "encoding/json"
 "errors"
 "io"
 "time"
)

// DurableSnapshot is a versioned, strictly decoded representation of a task.
// It is a serialization contract, not a storage engine or authorization proof.
type DurableSnapshot struct {
 SchemaVersion uint32 `json:"schema_version"`
 ID string `json:"id"`
 ServerID uint64 `json:"server_id"`
 PackageSHA256 string `json:"package_sha256"`
 Version string `json:"version"`
 ReleaseSequence uint64 `json:"release_sequence"`
 State State `json:"state"`
 ExpiresAt time.Time `json:"expires_at"`
}

const MaxSnapshotSize = 4096

func EncodeSnapshot(t Transaction) ([]byte,error) {
 if _,err:=RecoveryDecision(t,time.Now());err!=nil { return nil,err }
 b,err:=json.Marshal(DurableSnapshot{
  SchemaVersion:1,ID:t.ID,ServerID:t.ServerID,PackageSHA256:t.PackageSHA256,
  Version:t.Version,ReleaseSequence:t.ReleaseSequence,State:t.State,ExpiresAt:t.ExpiresAt.UTC(),
 })
 if err!=nil { return nil,err }
 if len(b)>MaxSnapshotSize { return nil,errors.New("snapshot exceeds size limit") }
 return b,nil
}

// DecodeSnapshot rejects unknown, duplicate, absent and null fields. Loading a
// snapshot never authorizes execution; the caller must apply RecoveryDecision,
// authenticate the target and enforce a durable one-active-task-per-server lock.
func DecodeSnapshot(data []byte) (Transaction,error) {
 var zero Transaction
 if len(data)==0 || len(data)>MaxSnapshotSize { return zero,errors.New("invalid snapshot size") }
 required:=map[string]bool{
  "schema_version":false,"id":false,"server_id":false,"package_sha256":false,
  "version":false,"release_sequence":false,"state":false,"expires_at":false,
 }
 d:=json.NewDecoder(bytes.NewReader(data))
 tok,err:=d.Token()
 if err!=nil || tok!=json.Delim('{') { return zero,errors.New("snapshot must be an object") }
 for d.More() {
  tok,err=d.Token()
  k,ok:=tok.(string)
  seen,known:=required[k]
  if err!=nil || !ok || !known || seen { return zero,errors.New("unknown or duplicate snapshot field") }
  required[k]=true
  var raw json.RawMessage
  if err:=d.Decode(&raw);err!=nil { return zero,err }
  if bytes.Equal(bytes.TrimSpace(raw),[]byte("null")) { return zero,errors.New("null snapshot field") }
 }
 if tok,err=d.Token();err!=nil || tok!=json.Delim('}') { return zero,errors.New("invalid snapshot ending") }
 if _,err=d.Token();err!=io.EOF { return zero,errors.New("trailing snapshot data") }
 for _,seen:=range required { if !seen { return zero,errors.New("missing snapshot field") } }
 var s DurableSnapshot
 if err:=json.Unmarshal(data,&s);err!=nil { return zero,err }
 if s.SchemaVersion!=1 { return zero,errors.New("unsupported snapshot schema") }
 t:=Transaction{ID:s.ID,ServerID:s.ServerID,PackageSHA256:s.PackageSHA256,
  Version:s.Version,ReleaseSequence:s.ReleaseSequence,State:s.State,ExpiresAt:s.ExpiresAt}
 if _,err:=RecoveryDecision(t,time.Now());err!=nil { return zero,err }
 return t,nil
}

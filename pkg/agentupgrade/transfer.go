package agentupgrade

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "fmt"
 "hash"
 "io"
)

// Chunk is a bounded, ordered part of one immutable NZU package. The transport
// must authenticate the Agent and bind its transaction before using this type.
type Chunk struct {
 TaskID string
 ServerID uint64
 PackageSHA256 string
 Offset int64
 Data []byte
}

// Receiver validates a single sequential transfer, including final package
// integrity. The caller must use a private staging file, not an install path.
// A Receiver is single-use and is not safe for concurrent calls.
type Receiver struct {
 taskID string
 serverID uint64
 digest string
 size int64
 offset int64
 hash hash.Hash
 writer io.Writer
 finished bool
}

// NewReceiver rejects empty identities and oversized or zero-length packages.
func NewReceiver(taskID string, serverID uint64, digest string, size int64, writer io.Writer) (*Receiver,error) {
 if taskID=="" || serverID==0 || !digestPattern.MatchString(digest) ||
 size<=0 || size>MaxPackageSize || writer==nil {
  return nil,errors.New("invalid transfer identity or size")
 }
 return &Receiver{taskID:taskID,serverID:serverID,digest:digest,size:size,hash:sha256.New(),writer:writer},nil
}

// WriteChunk enforces contiguous offsets, exact transaction binding and a
// fixed maximum chunk size. A failed write invalidates this Receiver.
func (r *Receiver) WriteChunk(c Chunk) error {
 if r==nil || r.finished { return errors.New("transfer closed") }
 if c.TaskID!=r.taskID || c.ServerID!=r.serverID || c.PackageSHA256!=r.digest {
  r.finished=true
  return errors.New("transfer identity mismatch")
 }
 if c.Offset!=r.offset || len(c.Data)==0 || len(c.Data)>ChunkSize ||
 int64(len(c.Data))>r.size-r.offset {
  r.finished=true
  return errors.New("invalid chunk offset or length")
 }
 n,err:=r.writer.Write(c.Data)
 if err!=nil || n!=len(c.Data) {
  r.finished=true
  if err!=nil {return err}
  return io.ErrShortWrite
 }
 _,_ = r.hash.Write(c.Data)
 r.offset+=int64(n)
 return nil
}

// Finish validates the complete NZU byte stream. Successful Finish is not
// signature verification: the immutable staged file must also pass VerifyPackage.
func (r *Receiver) Finish() error {
 if r==nil || r.finished { return errors.New("transfer closed") }
 r.finished=true
 if r.offset!=r.size {return fmt.Errorf("incomplete transfer: %d/%d",r.offset,r.size)}
 if hex.EncodeToString(r.hash.Sum(nil))!=r.digest {return errors.New("package digest mismatch")}
 return nil
}

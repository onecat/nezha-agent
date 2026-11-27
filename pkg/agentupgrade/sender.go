package agentupgrade

import (
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "io"
)

// Sender reads an immutable NZU package from a trusted ReaderAt. It does not
// authorize an upgrade or provide transport authentication. The caller must
// authenticate the recipient and enforce an expiry and cancellation deadline.
// ReaderAt must refer to the exact immutable bytes previously verified.
type Sender struct {
 taskID string
 serverID uint64
 digest string
 size int64
 reader io.ReaderAt
}

// NewSender validates the exact package digest before any chunks are sent.
// This intentionally re-reads the immutable source to prevent a stale or
// substituted artifact from being streamed after initial package verification.
func NewSender(t Transaction, reader io.ReaderAt, size int64) (*Sender,error) {
 if reader==nil || t.ID=="" || t.ServerID==0 || !digestPattern.MatchString(t.PackageSHA256) ||
  size<=0 || size>MaxPackageSize || t.State!=StateTransferring {
  return nil,errors.New("invalid transfer source or task")
 }
 h:=sha256.New()
 n,err:=io.Copy(h,io.NewSectionReader(reader,0,size))
 if err!=nil { return nil,err }
 if n!=size || hex.EncodeToString(h.Sum(nil))!=t.PackageSHA256 {
  return nil,errors.New("transfer source digest mismatch")
 }
 return &Sender{taskID:t.ID,serverID:t.ServerID,digest:t.PackageSHA256,size:size,reader:reader},nil
}

// ChunkAt returns the next contiguous chunk at offset. A zero-length chunk is
// never emitted; done is true only at the exact end. The caller must advance
// offset by len(chunk.Data) after successful transport acknowledgement.
func (s *Sender) ChunkAt(offset int64) (chunk Chunk,done bool,err error) {
 if s==nil || offset<0 || offset>s.size {
  return Chunk{},false,errors.New("invalid transfer offset")
 }
 if offset==s.size { return Chunk{},true,nil }
 n:=int64(ChunkSize)
 if remaining:=s.size-offset;remaining<n { n=remaining }
 data:=make([]byte,int(n))
 read,err:=s.reader.ReadAt(data,offset)
 if err!=nil && !(err==io.EOF && read==len(data)) { return Chunk{},false,err }
 if read!=len(data) { return Chunk{},false,io.ErrUnexpectedEOF }
 return Chunk{TaskID:s.taskID,ServerID:s.serverID,PackageSHA256:s.digest,Offset:offset,Data:data},false,nil
}

package agentupgrade

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"
)

func TestBuildPackageRoundTrip(t *testing.T) {
	pub,priv,err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	for _,os := range []string{"linux","windows"} {
		t.Run(os,func(t *testing.T){
			binary := []byte("test data, not an executable")
			m := Manifest{Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:os,Arch:"amd64",SigningKeyID:"test",ReleaseSequence:2}
			var dst bytes.Buffer
			signed,err := BuildPackage(&dst,bytes.NewReader(binary),int64(len(binary)),m,priv)
			if err != nil { t.Fatal(err) }
			out,err := VerifyPackage(bytes.NewReader(dst.Bytes()),int64(dst.Len()),map[string]ed25519.PublicKey{"test":pub})
			if err != nil { t.Fatal(err) }
			if signed != out.Manifest { t.Fatal("manifest mismatch") }
			if err := signed.CheckUpgrade(os,"amd64","v0.30.00",1); err != nil { t.Fatal(err) }
			if _,err := BuildPackage(io.Discard,bytes.NewReader(binary),int64(len(binary)+1),m,priv); err == nil { t.Fatal("short binary accepted") }
			if _,err := BuildPackage(io.Discard,bytes.NewReader(binary),int64(len(binary)),m,nil); err == nil { t.Fatal("invalid key accepted") }
			m.ReleaseSequence=0
			if _,err := BuildPackage(io.Discard,bytes.NewReader(binary),int64(len(binary)),m,priv); err == nil { t.Fatal("invalid sequence accepted") }
		})
	}
}

type changingReader struct { reads int }
func (r *changingReader) ReadAt(p []byte, off int64)(int,error) {
	r.reads++
	for i:=range p { p[i]=byte(r.reads) }
	return len(p),nil
}

func TestBuildRejectsChangingBinary(t *testing.T) {
	_,priv,err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	m := Manifest{Version:"v0.30.01",MinAgentVersion:"v0.30.00",OS:"linux",Arch:"amd64",SigningKeyID:"test",ReleaseSequence:2}
	if _,err := BuildPackage(io.Discard,&changingReader{},32,m,priv); err == nil { t.Fatal("accepted changed binary") }
}

func TestBoundedWriter(t *testing.T) {
	var b bytes.Buffer
	w:=boundedWriter{w:&b,left:3}
	if _,err:=w.Write([]byte("abc"));err!=nil { t.Fatal(err) }
	if _,err:=w.Write([]byte("d"));err==nil { t.Fatal("accepted oversized output") }
	if b.String()!="abc" { t.Fatal("unexpected output") }
}

package agentupgrade

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func TestVerifyPackage(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	binary := []byte("test fixture, not executable")
	m := Manifest{FormatVersion:1, Component:"nezha-agent", Version:"v0.30.01", OS:"linux",
		Arch:"amd64", MinAgentVersion:"v0.30.00", ProtocolVersion:1, Filename:"nezha-agent",
		Size:int64(len(binary)), SHA256:fmt.Sprintf("%x",sha256.Sum256(binary)), SigningKeyID:"release-01", ReleaseSequence:2}
	data, err := json.Marshal(m)
	if err != nil { t.Fatal(err) }
	type entry struct { name string; data []byte; mode os.FileMode }
	makeZip := func(entries []entry) []byte {
		t.Helper()
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		for _, e := range entries {
			h := &zip.FileHeader{Name:e.name, Method:zip.Deflate}
			h.SetMode(e.mode)
			f, err := w.CreateHeader(h)
			if err != nil { t.Fatal(err) }
			if _, err := f.Write(e.data); err != nil { t.Fatal(err) }
		}
		if err := w.Close(); err != nil { t.Fatal(err) }
		return buf.Bytes()
	}
	signed := func(d, b []byte) []entry {
		return []entry{{"manifest.json",d,0600},{"manifest.sig",ed25519.Sign(priv,d),0600},{"nezha-agent",b,0700}}
	}
	keys := map[string]ed25519.PublicKey{"release-01":pub}
	valid := makeZip(signed(data,binary))
	out, err := VerifyPackage(bytes.NewReader(valid),int64(len(valid)),keys)
	if err != nil { t.Fatal(err) }
	if out.Manifest != m || out.PackageSHA256 != fmt.Sprintf("%x",sha256.Sum256(valid)) { t.Fatal("verification result mismatch") }
	badSig := signed(data,binary); badSig[1].data[0] ^= 1
	badPath := signed(data,binary); badPath[2].name = "../nezha-agent"
	duplicate := signed(data,binary); duplicate[2].name = "manifest.json"
	symlink := signed(data,binary); symlink[2].mode = os.ModeSymlink | 0777
	duplicateJSON := append(append([]byte(nil),data[:len(data)-1]...),[]byte(",\"version\":\"v0.30.02\"}")...)
	unknownJSON := append(append([]byte(nil),data[:len(data)-1]...),[]byte(",\"extra\":1}")...)
	changed := append([]byte(nil),binary...); changed[0] ^= 1
	for _, tc := range []struct{name string; entries []entry}{
		{"signature",badSig},{"digest",signed(data,changed)},{"path",badPath},
		{"duplicate entry",duplicate},{"symlink",symlink},{"duplicate JSON",signed(duplicateJSON,binary)},
		{"unknown JSON",signed(unknownJSON,binary)},{"extra entry",append(signed(data,binary),entry{"extra",nil,0600})},
	} {
		t.Run(tc.name,func(t *testing.T){
			z := makeZip(tc.entries)
			if _, err := VerifyPackage(bytes.NewReader(z),int64(len(z)),keys); err == nil { t.Fatal("accepted invalid package") }
		})
	}
	if _, err := VerifyPackage(bytes.NewReader(valid),int64(len(valid)),nil); err == nil { t.Fatal("accepted untrusted key") }
	if _, err := VerifyPackage(bytes.NewReader(valid),MaxPackageSize+1,keys); err == nil { t.Fatal("accepted oversized package") }
	if err := m.CheckUpgrade("linux","amd64","v0.30.00",1); err != nil { t.Fatal(err) }
	for _, tc := range []struct{os,arch,version string; seq uint64}{
		{"linux","arm64","v0.30.00",1},{"windows","amd64","v0.30.00",1},
		{"linux","amd64","v0.20.5",1},{"linux","amd64","v0.30.01",1},
		{"linux","amd64","v0.30.02",1},{"linux","amd64","v0.30.00",2},
	} {
		if err := m.CheckUpgrade(tc.os,tc.arch,tc.version,tc.seq); err == nil { t.Fatalf("accepted invalid upgrade %+v",tc) }
	}
}

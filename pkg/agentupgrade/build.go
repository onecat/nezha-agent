package agentupgrade

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

type boundedWriter struct {
	w io.Writer
	left int64
}

func (w *boundedWriter) Write(p []byte) (int,error) {
	if int64(len(p)) > w.left { return 0, errors.New("package exceeds size limit") }
	n, err := w.w.Write(p)
	w.left -= int64(n)
	if err == nil && n != len(p) { err = io.ErrShortWrite }
	return n,err
}

// BuildPackage is intended for an offline release tool, not a Dashboard handler.
// The caller supplies trusted release metadata and an immutable binary reader.
// The output must be discarded on any error; nothing is installed or executed.
func BuildPackage(dst io.Writer, binary io.ReaderAt, size int64, m Manifest, key ed25519.PrivateKey) (Manifest,error) {
	if size <= 0 || size > MaxPackageSize || len(key) != ed25519.PrivateKeySize {
		return Manifest{}, errors.New("invalid binary size or signing key")
	}
	m.FormatVersion = 1
	m.Component = "nezha-agent"
	m.ProtocolVersion = ProtocolVersion
	m.Filename = "nezha-agent"
	if m.OS == "windows" { m.Filename += ".exe" }
	m.Size = size
	h := sha256.New()
	n,err := io.Copy(h,io.NewSectionReader(binary,0,size))
	if err != nil { return Manifest{},err }
	if n != size { return Manifest{},io.ErrUnexpectedEOF }
	m.SHA256 = hex.EncodeToString(h.Sum(nil))
	if err := m.validate(); err != nil { return Manifest{},err }
	data,err := json.Marshal(m)
	if err != nil { return Manifest{},err }
	if int64(len(data)) > MaxManifestSize || size > MaxPackageSize-int64(len(data))-ed25519.SignatureSize {
		return Manifest{},errors.New("uncompressed package exceeds size limit")
	}
	w := zip.NewWriter(&boundedWriter{w:dst,left:MaxPackageSize})
	for _,item := range []struct{name string; data []byte}{
		{"manifest.json",data},{"manifest.sig",ed25519.Sign(key,data)},
	} {
		f,err := w.CreateHeader(&zip.FileHeader{Name:item.name,Method:zip.Store})
		if err != nil { return Manifest{},err }
		if _,err := f.Write(item.data); err != nil { return Manifest{},err }
	}
	header := &zip.FileHeader{Name:m.Filename,Method:zip.Deflate}
	header.SetMode(0700)
	f,err := w.CreateHeader(header)
	if err != nil { return Manifest{},err }
	h.Reset()
	n,err = io.Copy(io.MultiWriter(f,h),io.NewSectionReader(binary,0,size))
	if err != nil { return Manifest{},err }
	if n != size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		return Manifest{},errors.New("binary changed while packaging")
	}
	if err := w.Close(); err != nil { return Manifest{},err }
	return m,nil
}

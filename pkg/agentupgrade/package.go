// Package agentupgrade defines the common, side-effect-free verification rules
// for managed Agent releases. It does not install or execute package contents.
package agentupgrade

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const (
	MaxPackageSize int64 = 100 << 20
	MaxManifestSize int64 = 16 << 10
	ChunkSize = 256 << 10
	ProtocolVersion = 1
	ManagedUpgradeTaskType = 12
)

type Manifest struct {
	FormatVersion uint32 `json:"format_version"`
	Component string `json:"component"`
	Version string `json:"version"`
	OS string `json:"os"`
	Arch string `json:"arch"`
	MinAgentVersion string `json:"min_agent_version"`
	ProtocolVersion uint32 `json:"protocol_version"`
	Filename string `json:"filename"`
	Size int64 `json:"size"`
	SHA256 string `json:"sha256"`
	SigningKeyID string `json:"signing_key_id"`
	ReleaseSequence uint64 `json:"release_sequence"`
}

type VerifiedPackage struct {
	Manifest Manifest
	PackageSHA256 string
}

var (
	versionPattern = regexp.MustCompile("^v[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}$")
	keyPattern = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
	digestPattern = regexp.MustCompile("^[0-9a-f]{64}$")
)

func compareVersions(a, b string) (int, error) {
	if !versionPattern.MatchString(a) || !versionPattern.MatchString(b) {
		return 0, errors.New("invalid release version")
	}
	x, y := strings.Split(a[1:], "."), strings.Split(b[1:], ".")
	for i := range x {
		n, _ := strconv.Atoi(x[i])
		m, _ := strconv.Atoi(y[i])
		if n < m { return -1, nil }
		if n > m { return 1, nil }
	}
	return 0, nil
}

func platformAllowed(os, arch string) bool {
	switch os {
	case "linux": return arch == "amd64" || arch == "arm64" || arch == "386" || arch == "arm"
	case "windows": return arch == "amd64" || arch == "arm64"
	case "freebsd": return arch == "amd64"
	case "darwin": return arch == "amd64" || arch == "arm64"
	}
	return false
}

func (m Manifest) validate() error {
	if m.FormatVersion != 1 || m.Component != "nezha-agent" || m.ProtocolVersion != ProtocolVersion {
		return errors.New("unsupported package format, component or protocol")
	}
	if !platformAllowed(m.OS, m.Arch) { return errors.New("invalid target platform") }
	name := "nezha-agent"
	if m.OS == "windows" { name += ".exe" }
	if m.Filename != name { return errors.New("invalid executable filename") }
	if m.Size <= 0 || m.Size > MaxPackageSize || !digestPattern.MatchString(m.SHA256) {
		return errors.New("invalid binary size or digest")
	}
	if !keyPattern.MatchString(m.SigningKeyID) || m.ReleaseSequence == 0 {
		return errors.New("invalid signing key or release sequence")
	}
	cmp, err := compareVersions(m.Version, m.MinAgentVersion)
	if err != nil || cmp < 0 { return errors.New("invalid release version range") }
	return nil
}

// CheckUpgrade accepts only a forward release for this platform. The caller must
// load and persist highestSequence from trusted local state; explicit rollback
// is a separate transaction and must not lower the high-water mark.
func (m Manifest) CheckUpgrade(os, arch, currentVersion string, highestSequence uint64) error {
	if err := m.validate(); err != nil { return err }
	if m.OS != os || m.Arch != arch { return errors.New("platform mismatch") }
	if m.ReleaseSequence <= highestSequence { return errors.New("stale release sequence") }
	cmp, err := compareVersions(currentVersion, m.MinAgentVersion)
	if err != nil || cmp < 0 { return errors.New("current version below minimum") }
	cmp, err = compareVersions(m.Version, currentVersion)
	if err != nil || cmp <= 0 { return errors.New("not a forward upgrade") }
	return nil
}

// parseManifest rejects duplicate, missing and unknown keys (including alternate
// spellings). The signed bytes are never normalized or reserialized.
func parseManifest(data []byte) (Manifest, error) {
	var m Manifest
	fields := map[string]bool{
		"format_version":false,"component":false,"version":false,"os":false,
		"arch":false,"min_agent_version":false,"protocol_version":false,
		"filename":false,"size":false,"sha256":false,"signing_key_id":false,
		"release_sequence":false,
	}
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') { return m, errors.New("manifest must be an object") }
	for d.More() {
		k, err := d.Token()
		name, ok := k.(string)
		seen, known := fields[name]
		if err != nil || !ok || !known || seen { return m, errors.New("invalid or duplicate manifest key") }
		fields[name] = true
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil { return m, err }
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) { return m, errors.New("null manifest value") }
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') { return m, errors.New("invalid manifest end") }
	if _, err = d.Token(); err != io.EOF { return m, errors.New("trailing manifest data") }
	for _, seen := range fields { if !seen { return m, errors.New("missing manifest key") } }
	if err := json.Unmarshal(data, &m); err != nil { return m, err }
	return m, m.validate()
}

func readEntry(f *zip.File, max int64) ([]byte, error) {
	if f == nil || f.UncompressedSize64 > uint64(max) { return nil, errors.New("missing or oversized ZIP entry") }
	r, err := f.Open()
	if err != nil { return nil, err }
	defer r.Close()
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil { return nil, err }
	if int64(len(data)) > max || uint64(len(data)) != f.UncompressedSize64 { return nil, errors.New("ZIP entry size mismatch") }
	return data, nil
}

// VerifyPackage requires a stable ReaderAt (a private immutable staging file)
// and independently provisioned Ed25519 keys. No extraction to paths occurs.
// The caller must keep the same immutable bytes for later storage or installation.
func VerifyPackage(r io.ReaderAt, size int64, trustedKeys map[string]ed25519.PublicKey) (VerifiedPackage, error) {
	var out VerifiedPackage
	if size <= 0 || size > MaxPackageSize { return out, errors.New("invalid package size") }
	z, err := zip.NewReader(r, size)
	if err != nil { return out, err }
	if len(z.File) != 3 { return out, errors.New("expected exactly three ZIP entries") }
	entries := make(map[string]*zip.File, 3)
	var total uint64
	for _, f := range z.File {
		switch f.Name {
		case "manifest.json", "manifest.sig", "nezha-agent", "nezha-agent.exe":
		default: return out, errors.New("unknown ZIP entry")
		}
		if entries[f.Name] != nil || !f.Mode().IsRegular() || f.Flags&1 != 0 ||
			(f.Method != zip.Store && f.Method != zip.Deflate) {
			return out, errors.New("invalid or duplicate ZIP entry")
		}
		if f.UncompressedSize64 > uint64(MaxPackageSize)-total { return out, errors.New("uncompressed size limit exceeded") }
		total += f.UncompressedSize64
		entries[f.Name] = f
	}
	data, err := readEntry(entries["manifest.json"], MaxManifestSize)
	if err != nil { return out, err }
	sig, err := readEntry(entries["manifest.sig"], ed25519.SignatureSize)
	if err != nil { return out, err }
	m, err := parseManifest(data)
	if err != nil { return out, err }
	pub := trustedKeys[m.SigningKeyID]
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, data, sig) {
		return out, errors.New("untrusted or invalid release signature")
	}
	f := entries[m.Filename]
	if f == nil || f.UncompressedSize64 != uint64(m.Size) { return out, errors.New("binary size mismatch") }
	bin, err := f.Open()
	if err != nil { return out, err }
	h := sha256.New()
	n, copyErr := io.Copy(h, io.LimitReader(bin, m.Size+1))
	closeErr := bin.Close()
	if copyErr != nil { return out, copyErr }
	if closeErr != nil { return out, closeErr }
	if n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 { return out, errors.New("binary digest or size mismatch") }
	h.Reset()
	n, err = io.Copy(h, io.NewSectionReader(r, 0, size))
	if err != nil { return out, err }
	if n != size { return out, fmt.Errorf("package size mismatch: %d", n) }
	return VerifiedPackage{Manifest:m, PackageSHA256:hex.EncodeToString(h.Sum(nil))}, nil
}

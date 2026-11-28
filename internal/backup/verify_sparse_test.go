package backup

import (
	"archive/tar"
	"bytes"
	json "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// paxRecord is one record of a PAX extended header.
func paxRecord(k, v string) string {
	n := len(k) + len(v) + 3
	for {
		s := fmt.Sprintf("%d %s=%s\n", n, k, v)
		if len(s) == n {
			return s
		}
		n = len(s)
	}
}

func padBlock(b []byte) []byte {
	for len(b)%512 != 0 {
		b = append(b, 0)
	}
	return b
}

// sparseMember is a GNU PAX 1.0 sparse member: archive/tar turns it into a
// regular member of realsize bytes, almost all of them holes.
func sparseMember(t *testing.T, name string, realsize int64) []byte {
	t.Helper()
	recs := paxRecord("GNU.sparse.major", "1") + paxRecord("GNU.sparse.minor", "0") +
		paxRecord("GNU.sparse.name", name) + paxRecord("GNU.sparse.realsize", fmt.Sprint(realsize))
	data := padBlock([]byte("0\n"))
	// tar.Writer refuses to write sparse headers, so the blocks are built
	// by hand.
	out := ustarBlock(t, "PaxHeaders/x", tar.TypeXHeader, int64(len(recs)))
	out = append(out, padBlock([]byte(recs))...)
	out = append(out, ustarBlock(t, "GNUSparseFile.0/x", tar.TypeReg, int64(len(data)))...)
	return append(out, data...)
}

func ustarBlock(t *testing.T, name string, typ byte, size int64) []byte {
	t.Helper()
	b := make([]byte, 512)
	copy(b[0:], name)
	copy(b[100:], "0000600\x00")
	copy(b[108:], "0000000\x00")
	copy(b[116:], "0000000\x00")
	copy(b[124:], fmt.Sprintf("%011o\x00", size))
	copy(b[136:], "00000000000\x00")
	b[156] = typ
	copy(b[257:], "ustar\x0000")
	copy(b[148:156], "        ")
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

// A sparse member would let a few KB of archive declare GiB of content
// that verification hashes and copies; Go's own writer never produces one.
func TestVerifyRejectsSparseMembers(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	good, err := Write(t.TempDir(), f.contents())
	if err != nil {
		t.Fatal(err)
	}
	rawGood, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	members := readAll(t, rawGood)
	var m Manifest
	if err := json.Unmarshal(members[0].data, &m); err != nil {
		t.Fatal(err)
	}
	const size = 1 << 20
	m.Files = append(m.Files, fileOf("data/sparse", make([]byte, size)))
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	write := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	write(ManifestName, raw)
	for _, mb := range members[1:] {
		write(mb.name, mb.data)
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	out := append(buf.Bytes(), sparseMember(t, "data/sparse", size)...)
	out = append(out, make([]byte, 1024)...)
	p := filepath.Join(t.TempDir(), "sparse.tar")
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = VerifyWith(t.Context(), p, VerifyOptions{Secret: f.secret})
	if err == nil || !strings.Contains(err.Error(), `unexpected member "data/sparse"`) {
		t.Fatalf("sparse member accepted: %v", err)
	}
}

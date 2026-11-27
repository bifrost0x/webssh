package backup

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeCrafted writes a tar archive from headers, each followed by its
// data, with a manifest that lists files.
func writeCrafted(t *testing.T, m Manifest, entries []craftedEntry) string {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	all := append([]craftedEntry{{hdr: tar.Header{Typeflag: tar.TypeReg, Name: ManifestName, Mode: 0o600}, data: raw}}, entries...)
	for _, e := range all {
		h := e.hdr
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(&h); err != nil {
			t.Fatal(err)
		}
		if len(e.data) > 0 {
			if _, err := tw.Write(e.data); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "crafted.tar")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type craftedEntry struct {
	hdr  tar.Header
	data []byte
}

func fileOf(name string, data []byte) File {
	sum := sha256.Sum256(data)
	return File{Name: name, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
}

// The Go-specific malicious archives of the restore DoD (D-30: Go
// archives are read strictly): links, devices, directories, absolute and
// traversing paths, non-canonical names, members outside the manifest,
// a legacy member under go/ (go/deleted_users/ is never part of a backup,
// ID4), and a foreign SECRET_KEY.
func TestStrictGoArchivesRejected(t *testing.T) {
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
	var base Manifest
	if err := json.Unmarshal(members[0].data, &base); err != nil {
		t.Fatal(err)
	}
	reg := func(name string, data []byte) craftedEntry {
		return craftedEntry{hdr: tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o600}, data: data}
	}
	fixed := []craftedEntry{reg(members[1].name, members[1].data), reg(members[2].name, members[2].data), reg(members[3].name, members[3].data)}
	withExtra := func(name string, e craftedEntry) (Manifest, []craftedEntry) {
		m := base
		m.Files = append(append([]File(nil), base.Files...), fileOf(name, e.data))
		return m, append(append([]craftedEntry(nil), fixed...), e)
	}
	cases := map[string]func() (Manifest, []craftedEntry){
		"symlink member": func() (Manifest, []craftedEntry) {
			m, es := withExtra("data/known_hosts", reg("data/known_hosts", nil))
			es[3] = craftedEntry{hdr: tar.Header{Typeflag: tar.TypeSymlink, Name: "data/known_hosts", Linkname: "/etc/passwd"}}
			return m, es
		},
		"hardlink member": func() (Manifest, []craftedEntry) {
			m, es := withExtra("data/known_hosts", reg("data/known_hosts", nil))
			es[3] = craftedEntry{hdr: tar.Header{Typeflag: tar.TypeLink, Name: "data/known_hosts", Linkname: DatabaseName}}
			return m, es
		},
		"database as hardlink": func() (Manifest, []craftedEntry) {
			es := append([]craftedEntry(nil), fixed...)
			es[0] = craftedEntry{hdr: tar.Header{Typeflag: tar.TypeLink, Name: DatabaseName, Linkname: "/etc/shadow"}}
			return base, es
		},
		"device member": func() (Manifest, []craftedEntry) {
			m, es := withExtra("data/dev", reg("data/dev", nil))
			es[3] = craftedEntry{hdr: tar.Header{Typeflag: tar.TypeChar, Name: "data/dev", Devmajor: 1, Devminor: 3}}
			return m, es
		},
		"directory member": func() (Manifest, []craftedEntry) {
			es := append([]craftedEntry{{hdr: tar.Header{Typeflag: tar.TypeDir, Name: "data/", Mode: 0o700}}}, fixed...)
			return base, es
		},
		"absolute path": func() (Manifest, []craftedEntry) {
			return withExtra("data//etc/cron.d/x", reg("data//etc/cron.d/x", []byte("x")))
		},
		"traversal": func() (Manifest, []craftedEntry) {
			return withExtra("data/../escape", reg("data/../escape", []byte("x")))
		},
		"non-canonical path": func() (Manifest, []craftedEntry) {
			return withExtra("data/users/./x", reg("data/users/./x", []byte("x")))
		},
		"backslash path": func() (Manifest, []craftedEntry) { return withExtra(`data/users\x`, reg(`data/users\x`, []byte("x"))) },
		"go directory member": func() (Manifest, []craftedEntry) {
			return withExtra("data/go/deleted_users/1-x/manifest.json", reg("data/go/deleted_users/1-x/manifest.json", []byte("{}")))
		},
		"logs member": func() (Manifest, []craftedEntry) {
			return withExtra("data/logs/.webssh-go/keyring-material", reg("data/logs/.webssh-go/keyring-material", []byte("x")))
		},
		"member not in manifest": func() (Manifest, []craftedEntry) {
			return base, append(append([]craftedEntry(nil), fixed...), reg("data/extra", []byte("x")))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m, es := build()
			p := writeCrafted(t, m, es)
			if _, err := VerifyWith(t.Context(), p, VerifyOptions{Secret: f.secret}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
	// The manifest with an extra member is refused although every file
	// verifies.
	extra := append(bytes.TrimSuffix(members[0].data, []byte("}")), []byte(`,"extra":1}`)...)
	p := writeCrafted2(t, extra, fixed)
	if _, err := VerifyWith(t.Context(), p, VerifyOptions{Secret: f.secret}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("extra manifest member accepted: %v", err)
	}
}

// writeCrafted2 writes a raw manifest followed by entries.
func writeCrafted2(t *testing.T, manifest []byte, entries []craftedEntry) string {
	t.Helper()
	var ms []member
	ms = append(ms, member{ManifestName, manifest})
	for _, e := range entries {
		ms = append(ms, member{e.hdr.Name, e.data})
	}
	p := filepath.Join(t.TempDir(), "raw.tar")
	if err := os.WriteFile(p, buildTar(ms), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

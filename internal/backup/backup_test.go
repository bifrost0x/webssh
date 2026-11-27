package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

var probeSchema = store.Schema{Owner: "vault", Migrations: []store.Migration{{Version: 1,
	SQL: `CREATE TABLE vault_probe (id TEXT PRIMARY KEY, sealed BLOB NOT NULL) STRICT`}}}

func probeAAD() keyring.AAD { return keyring.AAD{Table: "vault_probe", Column: "sealed", Row: "1"} }

func probe(ctx context.Context, tx *store.Tx, ring *keyring.Ring) (bool, error) {
	var sealed []byte
	if err := tx.QueryRowContext(ctx, `SELECT sealed FROM vault_probe`).Scan(&sealed); err != nil {
		return false, err
	}
	_, err := ring.Open(keyring.SSHKey, probeAAD(), sealed)
	return true, err
}

type fixture struct {
	dir      string
	db       string
	secret   []byte
	material []byte
	ring     *keyring.Ring
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	f := fixture{dir: t.TempDir(), secret: []byte("backup-test-secret-0123456789abcdef"), material: make([]byte, keyring.MaterialSize)}
	_, _ = rand.Read(f.material)
	ring, err := keyring.Open(f.secret, f.material)
	if err != nil {
		t.Fatal(err)
	}
	f.ring = ring
	f.db = filepath.Join(f.dir, "webssh.db")
	db, err := store.Open(t.Context(), f.db, store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := ring.Seal(keyring.SSHKey, probeAAD(), []byte("private key"))
	if err == nil {
		err = db.ApplyAll(t.Context(), probeSchema)
	}
	if err == nil {
		err = db.Write(t.Context(), func(tx *store.Tx) error {
			_, err := tx.ExecContext(t.Context(), `INSERT INTO vault_probe VALUES ('1', ?)`, sealed)
			return err
		})
	}
	if err := errors.Join(err, db.CloseForActivation(t.Context())); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) contents() Contents {
	return Contents{Database: f.db, SecretKey: f.secret, Material: f.material, KeyID: f.ring.KeyID(), Release: "test",
		Reason: "legacy-purge", Now: time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)}
}

func TestWriteVerify(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	out := t.TempDir()
	path, err := Write(out, f.contents())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("archive mode: %v, %v", info, err)
	}
	v, err := Verify(t.Context(), path, probe)
	if err != nil || !v.SealedChecked || v.Manifest.KeyID != f.ring.KeyID() || len(v.Manifest.Files) != 3 {
		t.Fatalf("%+v, %v", v, err)
	}
	if entries, _ := os.ReadDir(out); len(entries) != 1 {
		t.Errorf("verification left files behind: %v", entries)
	}
	if _, err := Write(out, f.contents()); err == nil {
		t.Error("an existing archive was overwritten")
	}
}

// Every damage to the archive fails verification.
func TestVerifyRejects(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	path, err := Write(t.TempDir(), f.contents())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	members := readAll(t, raw)
	otherMaterial := bytes.Repeat([]byte{7}, keyring.MaterialSize)
	cases := map[string][]member{
		"no manifest first": {members[1], members[0], members[2], members[3]},
		"member missing":    {members[0], members[1], members[2]},
		"member twice":      {members[0], members[1], members[2], members[3], members[3]},
		"foreign material":  {members[0], members[1], members[2], {members[3].name, otherMaterial}},
		"flipped database":  {members[0], {members[1].name, flip(members[1].data, 200)}, members[2], members[3]},
		"other order":       {members[0], members[2], members[1], members[3]},
		"bad manifest":      {{ManifestName, []byte("{}")}, members[1], members[2], members[3]},
	}
	for name, ms := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			p := filepath.Join(t.TempDir(), "a.tar")
			if err := os.WriteFile(p, buildTar(ms), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(t.Context(), p, probe); !errors.Is(err, ErrInvalid) {
				t.Errorf("got %v", err)
			}
		})
	}
	// A probe that fails to open a record fails the archive.
	failing := func(context.Context, *store.Tx, *keyring.Ring) (bool, error) { return true, errors.New("decrypt") }
	if _, err := Verify(t.Context(), path, failing); !errors.Is(err, ErrInvalid) {
		t.Errorf("failing probe: %v", err)
	}
}

func TestWriteRequiresContents(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.contents()
	c.Material = nil
	if _, err := Write(t.TempDir(), c); err == nil {
		t.Error("an archive with SECRET_KEY but without the material was written")
	}
	c = f.contents()
	c.KeyID = ""
	if _, err := Write(t.TempDir(), c); err == nil {
		t.Error("an archive without key id was written")
	}
}

// D-08: an archive without SECRET_KEY opens only with the active secret;
// one without material only with the installation's material. The purge
// verification requires both in the archive.
func TestOptionalSecretAndMaterial(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	c := f.contents()
	c.SecretKey, c.Reason = nil, ReasonExport
	path, err := Write(t.TempDir(), c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(t.Context(), path, probe); !errors.Is(err, ErrInvalid) {
		t.Fatalf("purge verification accepted an archive without SECRET_KEY: %v", err)
	}
	if _, err := VerifyWith(t.Context(), path, VerifyOptions{Probes: []Probe{probe}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no secret at all: %v", err)
	}
	if _, err := VerifyWith(t.Context(), path, VerifyOptions{Secret: []byte("another-secret-0123456789abcdef")}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong secret: %v", err)
	}
	v, err := VerifyWith(t.Context(), path, VerifyOptions{Secret: f.secret, Probes: []Probe{probe}})
	if err != nil || !v.SealedChecked || v.Manifest.IncludesSecretKey || !bytes.Equal(v.Material, f.material) {
		t.Fatalf("%+v, %v", v, err)
	}

	c.Material, c.Reason = nil, ReasonReplaced
	path, err = Write(t.TempDir(), c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(t.Context(), path, VerifyOptions{Secret: f.secret}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no material: %v", err)
	}
	other := bytes.Repeat([]byte{9}, keyring.MaterialSize)
	if _, err := VerifyWith(t.Context(), path, VerifyOptions{Secret: f.secret, Material: other}); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("foreign material: %v", err)
	}
	keep := filepath.Join(t.TempDir(), "kept.db")
	if _, err := VerifyWith(t.Context(), path, VerifyOptions{Secret: f.secret, Material: f.material, Probes: []Probe{probe}, Database: keep}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(keep); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("kept database: %v, %v", info, err)
	}
}

// An archive with another SECRET_KEY than the active one is refused.
func TestSecretMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	path, err := Write(t.TempDir(), f.contents())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyWith(t.Context(), path, VerifyOptions{Secret: []byte("active-secret-0123456789abcdef")}); !errors.Is(err, ErrSecretMismatch) {
		t.Fatalf("got %v", err)
	}
	if _, err := VerifyWith(t.Context(), path, VerifyOptions{Secret: f.secret}); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyLimits(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	path, err := Write(t.TempDir(), f.contents())
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]Limits{
		"members":   {MaxMembers: 3, MaxFileSize: 1 << 30, MaxTotalSize: 1 << 30, MaxManifestSize: 1 << 20},
		"file size": {MaxMembers: 10, MaxFileSize: 1000, MaxTotalSize: 1 << 30, MaxManifestSize: 1 << 20},
		"total":     {MaxMembers: 10, MaxFileSize: 1 << 30, MaxTotalSize: 2000, MaxManifestSize: 1 << 20},
		"manifest":  {MaxMembers: 10, MaxFileSize: 1 << 30, MaxTotalSize: 1 << 30, MaxManifestSize: 10},
	} {
		if _, err := VerifyWith(t.Context(), path, VerifyOptions{Limits: l}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

type member struct {
	name string
	data []byte
}

func readAll(t *testing.T, raw []byte) []member {
	t.Helper()
	var out []member
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(tr)
		out = append(out, member{h.Name, b})
	}
}

func buildTar(ms []member) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range ms {
		_ = tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: m.name, Size: int64(len(m.data)), Mode: 0o600})
		_, _ = tw.Write(m.data)
	}
	_ = tw.Close()
	return buf.Bytes()
}

func flip(b []byte, i int) []byte {
	c := bytes.Clone(b)
	c[i] ^= 0xff
	return c
}

// FuzzVerify feeds arbitrary archives to the reader; it must fail cleanly.
func FuzzVerify(f *testing.F) {
	f.Add([]byte{})
	f.Add(buildTar([]member{{ManifestName, []byte(`{"format":"webssh-go-backup","version":1}`)}}))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "a.tar")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(context.Background(), p); err == nil {
			t.Fatal("arbitrary data verified")
		}
	})
}

// Legacy files kept in place go into the archive below data/ and are
// verified by their hash; anything outside the data directory, in go/ or
// logs/, SECRET_KEY, a duplicate and a link out of the data directory is
// refused.
func TestWriteVerifyLegacy(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	data := t.TempDir()
	for name, body := range map[string]string{"users/user_9/settings.json": "{}", "deleted_users/user_3_x/keys/a": "key"} {
		p := filepath.Join(data, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(data, "link")); err != nil {
		t.Fatal(err)
	}
	c := f.contents()
	c.DataDir, c.Legacy = data, []string{"users/user_9/settings.json", "deleted_users/user_3_x/keys/a"}
	path, err := Write(t.TempDir(), c)
	if err != nil {
		t.Fatal(err)
	}
	v, err := Verify(t.Context(), path, probe)
	if err != nil || len(v.Manifest.Files) != 5 || v.Manifest.Files[4].Name != "data/deleted_users/user_3_x/keys/a" {
		t.Fatalf("%+v, %v", v, err)
	}
	for _, bad := range [][]string{{"../x"}, {"go/webssh.db"}, {"logs/a"}, {"secret_key"}, {"a/../b"}, {"link"},
		{"users/user_9/settings.json", "users/user_9/settings.json"}, {"missing"}, {"users"}} {
		c.Legacy = bad
		if _, err := Write(t.TempDir(), c); err == nil {
			t.Errorf("legacy %q written", bad)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ms := readAll(t, raw)
	cases := map[string][]member{
		"legacy file changed":  {ms[0], ms[1], ms[2], ms[3], {ms[4].name, []byte("other")}, ms[5]},
		"legacy file missing":  {ms[0], ms[1], ms[2], ms[3], ms[4]},
		"legacy files swapped": {ms[0], ms[1], ms[2], ms[3], ms[5], ms[4]},
	}
	for name, members := range cases {
		p := filepath.Join(t.TempDir(), "a.tar")
		if err := os.WriteFile(p, buildTar(members), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(t.Context(), p, probe); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestLegacyMember(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"data/users/user_1/a": true, "data/app.db": true, "data/go/x": false, "data/logs/x": false, "data/secret_key": false,
		"data/": false, "users/a": false, "data/../a": false, "data/a//b": false, "data/a\\b": false, "data//a": false,
	} {
		if got := LegacyMember(name); got != want {
			t.Errorf("%q: %v", name, got)
		}
	}
}

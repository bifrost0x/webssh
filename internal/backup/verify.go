package backup

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

// Errors of verification. Every one also matches ErrInvalid.
var (
	// ErrInvalid reports an archive that fails verification.
	ErrInvalid = errors.New("backup: the archive does not verify")
	// ErrSecretMismatch reports an archive whose SECRET_KEY is not the
	// active one where the restore may not adopt it (SECRET_KEY from the
	// environment, VerifyOptions.AdoptSecret).
	ErrSecretMismatch = fmt.Errorf("%w: the archive was made with another SECRET_KEY", ErrInvalid)
	// ErrKeyMismatch reports SECRET_KEY and material that do not give the
	// archive's key identifier.
	ErrKeyMismatch = fmt.Errorf("%w: SECRET_KEY and the keyring material do not match the archive's key id", ErrInvalid)
)

// Probe opens one sealed record of a capability with ring and reports
// whether there was one (vault.ProbeSealed, totp.ProbeSealed).
type Probe func(ctx context.Context, tx *store.Tx, ring *keyring.Ring) (bool, error)

// Verified is the outcome of Verify.
type Verified struct {
	Manifest Manifest
	// SealedChecked is true when a probe found and opened a sealed
	// record; a database without sealed records has none to open.
	SealedChecked bool
	// Material is the keyring material that opened the archive: its own,
	// or VerifyOptions.Material for an archive without one.
	Material []byte
	// Ring is the keyring the archive's records belong to.
	Ring *keyring.Ring
	// Secret is the SECRET_KEY that opened the archive: its own, or
	// VerifyOptions.Secret for an archive without one.
	Secret []byte
}

// VerifyOptions configure VerifyWith.
type VerifyOptions struct {
	// Secret is the active SECRET_KEY. An archive with SECRET_KEY must
	// carry this one (ErrSecretMismatch); an archive without one is
	// opened with it. Nil accepts the archive's SECRET_KEY.
	Secret []byte
	// AdoptSecret accepts an archive whose SECRET_KEY differs from Secret
	// (the restore on an installation that keeps SECRET_KEY in
	// DATA_DIR/secret_key, which the Python release replaced with the
	// archive's file).
	AdoptSecret bool
	// Material opens an archive without keyring material.
	Material []byte
	// RequireSecret refuses an archive without SECRET_KEY and material
	// (the purge backup).
	RequireSecret bool
	// Limits bound the archive; the zero value is DefaultLimits.
	Limits Limits
	// Probes open one sealed record each, until one is found.
	Probes []Probe
	// Database, if set, receives the verified database (a new file, mode
	// 0600); otherwise the copy is removed.
	Database string
}

// Verify reads an archive back and requires SECRET_KEY and the material
// in it (the purge backup): see VerifyWith.
func Verify(ctx context.Context, path string, probes ...Probe) (Verified, error) {
	return VerifyWith(ctx, path, VerifyOptions{RequireSecret: true, Probes: probes})
}

// VerifyWith reads an archive back strictly (D-30): the manifest, the
// name, type, size and SHA-256 of every member in the order the manifest
// lists them, the limits, the integrity of the database, the key
// identifier of SECRET_KEY and the material, and one sealed record per
// probe until one is found. Links, devices, directories and members the
// manifest does not name are refused. The database is checked on a
// temporary copy next to the archive (or at o.Database).
func VerifyWith(ctx context.Context, path string, o VerifyOptions) (Verified, error) {
	var v Verified
	if o.Limits == (Limits{}) {
		o.Limits = DefaultLimits
	}
	f, err := os.Open(path) // #nosec G304 G703 -- the archive to verify, named by the operator or an operation
	if err != nil {
		return v, fmt.Errorf("backup: open %s: %w", path, err)
	}
	defer f.Close()
	tmp, err := os.MkdirTemp(filepath.Dir(path), ".webssh-backup-verify-")
	if err != nil {
		return v, fmt.Errorf("backup: verify %s: %w", path, err)
	}
	defer os.RemoveAll(tmp)
	dbCopy := filepath.Join(tmp, "webssh.db")
	members, err := readMembers(tar.NewReader(f), &v.Manifest, dbCopy, o.Limits)
	if err != nil {
		return v, err
	}
	if v.Ring, v.Material, v.Secret, err = openRing(v.Manifest, members, o); err != nil {
		return v, err
	}
	if v.SealedChecked, err = checkDatabase(ctx, dbCopy, v.Ring, o.Probes); err != nil {
		return v, err
	}
	if o.Database != "" {
		if err := moveFile(dbCopy, o.Database); err != nil {
			return v, fmt.Errorf("backup: keep the verified database: %w", err)
		}
	}
	return v, nil
}

func openRing(m Manifest, members map[string][]byte, o VerifyOptions) (*keyring.Ring, []byte, []byte, error) {
	secret, material := members[SecretName], members[MaterialName]
	if o.RequireSecret && (secret == nil || material == nil) {
		return nil, nil, nil, fmt.Errorf("%w: SECRET_KEY and the material are required", ErrInvalid)
	}
	switch {
	case secret != nil && o.Secret != nil && !o.AdoptSecret && subtle.ConstantTimeCompare(secret, o.Secret) != 1:
		return nil, nil, nil, ErrSecretMismatch
	case secret == nil && o.Secret == nil:
		return nil, nil, nil, fmt.Errorf("%w: the archive holds no SECRET_KEY", ErrInvalid)
	case secret == nil:
		secret = o.Secret
	}
	if material == nil {
		material = o.Material
	}
	if material == nil {
		return nil, nil, nil, fmt.Errorf("%w: the archive holds no keyring material, and none was given", ErrInvalid)
	}
	ring, err := keyring.Open(secret, material)
	if err == nil {
		err = ring.Verify(m.KeyID)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: %w", ErrKeyMismatch, err)
	}
	return ring, material, secret, nil
}

// fixedMembers are the members before the kept legacy files, in order,
// as the manifest must list them.
func fixedMembers(m *Manifest) ([]string, error) {
	want := []string{DatabaseName}
	if m.IncludesSecretKey {
		want = append(want, SecretName)
	}
	if len(m.Files) > len(want) && m.Files[len(want)].Name == MaterialName {
		want = append(want, MaterialName)
	}
	if len(m.Files) < len(want) {
		return nil, fmt.Errorf("%w: members are missing", ErrInvalid)
	}
	for i, name := range want {
		if m.Files[i].Name != name {
			return nil, fmt.Errorf("%w: unexpected member %q in the manifest", ErrInvalid, m.Files[i].Name)
		}
	}
	return want, nil
}

func checkManifest(m *Manifest, l Limits) ([]string, int, error) {
	if m.Format != FormatName || m.Version != FormatVersion || m.KeyID == "" {
		return nil, 0, fmt.Errorf("%w: unsupported manifest", ErrInvalid)
	}
	if len(m.Files)+1 > l.MaxMembers {
		return nil, 0, fmt.Errorf("%w: too many members", ErrInvalid)
	}
	want, err := fixedMembers(m)
	if err != nil {
		return nil, 0, err
	}
	fixed := len(want)
	var total int64
	for i, f := range m.Files {
		if f.Size < 0 || f.Size > l.MaxFileSize {
			return nil, 0, fmt.Errorf("%w: member %q exceeds the size limit", ErrInvalid, f.Name)
		}
		if total += f.Size; total > l.MaxTotalSize {
			return nil, 0, fmt.Errorf("%w: the archive exceeds the size limit", ErrInvalid)
		}
		if i < fixed {
			continue
		}
		if !LegacyMember(f.Name) || slices.Contains(want, f.Name) {
			return nil, 0, fmt.Errorf("%w: unexpected member %q in the manifest", ErrInvalid, f.Name)
		}
		want = append(want, f.Name)
	}
	return want, fixed, nil
}

// readMembers checks the manifest and every member. The database is
// written to dbCopy, the small members are returned.
func readMembers(tr *tar.Reader, m *Manifest, dbCopy string, l Limits) (map[string][]byte, error) {
	limit := min(int64(maxManifest), l.MaxManifestSize)
	h, err := tr.Next()
	if err != nil || h.Name != ManifestName || h.Typeflag != tar.TypeReg || h.Size > limit {
		return nil, fmt.Errorf("%w: the first member is not the manifest", ErrInvalid)
	}
	raw, err := io.ReadAll(io.LimitReader(tr, limit))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if err := json.Unmarshal(raw, m, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("%w: manifest: %w", ErrInvalid, err)
	}
	want, fixed, err := checkManifest(m, l)
	if err != nil {
		return nil, err
	}
	small := map[string][]byte{}
	seen := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		i := seen
		if seen >= len(want) || want[seen] != h.Name || h.Typeflag != tar.TypeReg || h.Linkname != "" || h.Size != m.Files[i].Size {
			return nil, fmt.Errorf("%w: unexpected member %q", ErrInvalid, h.Name)
		}
		seen++
		if err := readMember(tr, h, m.Files[i], i >= fixed, dbCopy, small); err != nil {
			return nil, err
		}
	}
	if seen != len(want) {
		return nil, fmt.Errorf("%w: members are missing", ErrInvalid)
	}
	return small, nil
}

func readMember(tr *tar.Reader, h *tar.Header, want File, legacy bool, dbCopy string, small map[string][]byte) error {
	var dst io.Writer
	var buf bytes.Buffer
	var out *os.File
	var err error
	switch {
	case legacy:
		dst = io.Discard // a kept legacy file: only its hash is checked
	case h.Name == DatabaseName:
		if out, err = os.OpenFile(dbCopy, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600); err != nil { // #nosec G304 G703 -- a private temporary directory
			return err
		}
		dst = out
	default:
		if h.Size > keyring.MaterialSize*1024 {
			return fmt.Errorf("%w: member %q is too large", ErrInvalid, h.Name)
		}
		dst = &buf
	}
	sum := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, sum), io.LimitReader(tr, want.Size+1))
	if out != nil {
		err = errors.Join(err, out.Close())
	}
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	if n != want.Size || hex.EncodeToString(sum.Sum(nil)) != want.SHA256 {
		return fmt.Errorf("%w: %s does not match its hash", ErrInvalid, h.Name)
	}
	if out == nil && !legacy {
		small[h.Name] = buf.Bytes()
	}
	return nil
}

func checkDatabase(ctx context.Context, path string, ring *keyring.Ring, probes []Probe) (bool, error) {
	db, err := store.Open(ctx, path, store.Options{})
	if err != nil {
		return false, fmt.Errorf("%w: database: %w", ErrInvalid, err)
	}
	if err := db.IntegrityCheck(ctx); err != nil {
		return false, errors.Join(fmt.Errorf("%w: database: %w", ErrInvalid, err), db.Close())
	}
	checked := false
	err = db.Read(ctx, func(tx *store.Tx) error {
		for _, p := range probes {
			found, err := p(ctx, tx, ring)
			if err != nil {
				return err
			}
			if found {
				checked = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		return false, errors.Join(fmt.Errorf("%w: sealed record: %w", ErrInvalid, err), db.Close())
	}
	// Closed like a database to activate: no side file stays behind.
	if err := db.CloseForActivation(ctx); err != nil {
		return false, fmt.Errorf("%w: database: %w", ErrInvalid, err)
	}
	return checked, nil
}

// moveFile renames from to a new path to; across file systems it copies,
// syncs and removes the original.
func moveFile(from, to string) error {
	if _, err := os.Lstat(to); err == nil {
		return fmt.Errorf("%s exists", to)
	}
	if err := os.Rename(from, to); err == nil { // #nosec G703 -- Go-owned staging paths
		return syncDir(filepath.Dir(to))
	}
	in, err := os.Open(from) // #nosec G304 G703 -- a private temporary file
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- a path the caller owns
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err = errors.Join(err, out.Sync(), out.Close()); err != nil {
		return errors.Join(err, os.Remove(to))
	}
	return errors.Join(syncDir(filepath.Dir(to)), os.Remove(from)) // #nosec G703 -- Go-owned staging paths
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// syncDir makes the new archive's directory entry durable. Windows cannot
// sync a directory.
func syncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	d, err := os.Open(dir) // #nosec G304 -- the backup target
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

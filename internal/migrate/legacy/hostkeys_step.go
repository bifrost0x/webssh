package legacy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/ssh/hostkey"
	"github.com/bifrost0x/webssh/internal/store"
)

// hostKeysStep migrates the trusted host keys: entity E17, the global
// DATA_DIR/known_hosts, or entity E24, users/user_N/known_hosts of each
// account. Each file is stored byte for byte per scope
// (hostkey.ImportFile), which parses it like the Python release; an
// invalid line stops the migration (Python rejects the whole file).
// @cert-authority lines are kept and FLAGged: Python ignores them.
type hostKeysStep struct {
	entity string
	files  []knownHosts
}

type knownHosts struct {
	owner    int64 // 0 for the global file
	path     string
	raw      []byte
	modified time.Time
	legacy   []HostKey
}

func (s *hostKeysStep) Entity() string { return s.entity }

func (*hostKeysStep) Version() int { return 1 }

// accountScoped: the known_hosts files of the accounts (E24) are read one
// account at a time; the global file (E17) is one step.
func (s *hostKeysStep) accountScoped() bool { return s.entity == "E24" }

func (s *hostKeysStep) scope() hostkey.Scope {
	if s.entity == "E17" {
		return hostkey.ScopeGlobal
	}
	return hostkey.ScopeUser
}

func (s *hostKeysStep) Read(ctx context.Context, src *Source) error {
	if s.scope() == hostkey.ScopeGlobal {
		return s.readFile(src, 0, "known_hosts")
	}
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		if err := s.readFile(src, a.ID, userDir(a.ID)+"/known_hosts"); err != nil {
			return err
		}
	}
	return nil
}

func (s *hostKeysStep) readFile(src *Source, owner int64, path string) error {
	info, err := lstatChain(src.root, path)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	raw, err := src.readFile(path)
	if err != nil {
		return err
	}
	legacy, err := parseKnownHosts(raw)
	if err != nil {
		return &StepError{UserID: owner, Record: path, Err: err}
	}
	s.files = append(s.files, knownHosts{owner: owner, path: path, raw: raw, modified: info.ModTime().UTC(), legacy: legacy})
	return nil
}

func (s *hostKeysStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, f := range s.files {
		if err := hostkey.ImportFile(ctx, tx, s.scope(), f.owner, f.raw, f.modified); err != nil {
			return &StepError{UserID: f.owner, Record: f.path, Err: err}
		}
	}
	return nil
}

// Verify reads each file back and parses it with the host-key store's
// parser: the bytes are equal, and the trusted, revoked and
// certificate-authority keys are the ones the legacy parser found.
func (s *hostKeysStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, f := range s.files {
		raw, found, err := hostkey.FileTx(ctx, tx, s.scope(), f.owner)
		if err != nil || !found || !bytes.Equal(raw, f.raw) {
			return &StepError{UserID: f.owner, Record: f.path, Err: errors.Join(errors.New("legacy: the stored known_hosts differs"), err)}
		}
		parsed, err := hostkey.Parse(raw)
		if err != nil {
			return &StepError{UserID: f.owner, Record: f.path, Err: err}
		}
		var want, got []string
		for _, k := range f.legacy {
			want = append(want, k.Marker+" "+k.Fingerprint)
		}
		for marker, entries := range map[string][]hostkey.Entry{"": parsed.Trusted, "revoked": parsed.Revoked, "cert-authority": parsed.CertAuthorities} {
			for _, e := range entries {
				got = append(got, marker+" "+ssh.FingerprintSHA256(e.Key))
			}
		}
		slices.Sort(want)
		slices.Sort(got)
		if !slices.Equal(want, got) {
			return &StepError{UserID: f.owner, Record: f.path, Err: errors.New("legacy: the stored host keys differ from the legacy keys")}
		}
	}
	return nil
}

func (s *hostKeysStep) Report() StepReport {
	r := StepReport{Entity: s.entity, Version: 1}
	for _, f := range s.files {
		r.Read += len(f.legacy)
		r.Written += len(f.legacy)
		for _, k := range f.legacy {
			if k.Marker == "cert-authority" {
				r.Flagged = append(r.Flagged, Flag{UserID: f.owner, ID: f.path,
					Reason: "cert_authority_line: kept, but not used, as in the Python release (" + strconv.Quote(k.Fingerprint) + ")"})
			}
		}
	}
	switch {
	case s.accountScoped() && len(s.files) > 0:
		r.accountNote, r.accounts = "%d known_hosts file(s) stored byte for byte", len(s.files)
	case len(s.files) > 0:
		r.Notes = append(r.Notes, fmt.Sprintf("%d known_hosts file(s) stored byte for byte", len(s.files)))
	}
	return r
}

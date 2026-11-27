package legacy

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"

	"github.com/bifrost0x/webssh/internal/hosts"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

// AddCredentials registers the steps of the area "credentials": the saved
// passwords (E32) and the legacy automation vault (E30). They take over
// the entities the M1 release keeps in place.
func AddCredentials(r *Registry) error {
	return errors.Join(
		r.Add(GroupAutomation, func() Step { return &credentialsStep{} }),
		r.Add(GroupAutomation, func() Step { return &legacyVaultStep{} }),
	)
}

// credentialsStep migrates entity E32: credentials.json of every account,
// each password decrypted with SECRET_KEY and sealed through the vault,
// the assignments with their fingerprint and generation and the imported
// vault revisions unchanged, all in the order of the document.
type credentialsStep struct {
	users []userCredentials
}

type userCredentials struct {
	id          int64
	creds       []NamedCredential
	assignments []vault.Assignment
	imports     []string
	dropped     int // non-text import entries, which can never match
	// status is the state of each assignment against the legacy records,
	// as the Python release showed it.
	status map[string]vault.Status
	smb    []jsontext.Value
}

func (*credentialsStep) Entity() string { return "E32" }

func (*credentialsStep) Version() int { return 1 }

func (*credentialsStep) accountScoped() bool { return true }

func (s *credentialsStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	legacyHosts, err := readUserHosts(ctx, src)
	if err != nil {
		return err
	}
	for _, a := range rows {
		creds, refs, err := src.NamedCredentials(ctx, a.ID)
		if err != nil {
			return &StepError{UserID: a.ID, Record: "credentials.json", Err: err}
		}
		if creds == nil && refs == nil {
			continue
		}
		raw, err := src.readStoreBytes(userDir(a.ID)+"/credentials.json", "credentials")
		if err != nil {
			return &StepError{UserID: a.ID, Record: "credentials.json", Err: err}
		}
		u := userCredentials{id: a.ID, status: map[string]vault.Status{}}
		if err := u.order(raw, creds, refs); err != nil {
			return &StepError{UserID: a.ID, Record: "credentials.json", Err: err}
		}
		if u.smb, err = smbShares(src, a.ID); err != nil {
			return err
		}
		var lh hosts.Legacy
		if i := slices.IndexFunc(legacyHosts, func(h userHosts) bool { return h.id == a.ID }); i >= 0 {
			lh = legacyHosts[i].legacy
		}
		u.status = assignmentStatus(lh, u.smb, u.assignments)
		s.users = append(s.users, u)
	}
	return nil
}

// order puts the records, assignments and imports in document order;
// NamedCredentials checked and decrypted them.
func (u *userCredentials) order(raw []byte, creds []NamedCredential, refs map[string]CredentialAssignment) error {
	doc, _, err := pyjson.Load(raw)
	if err != nil {
		return err
	}
	section := func(name string) []pyjson.Member {
		v, _ := pyjson.Get(doc, name)
		m, _ := pyjson.Members(v)
		return m
	}
	for _, m := range section("credentials") {
		i := slices.IndexFunc(creds, func(c NamedCredential) bool { return c.ID == m.Name })
		if i < 0 {
			return errors.New("legacy: credential order differs")
		}
		u.creds = append(u.creds, creds[i])
	}
	for _, m := range section("assignments") {
		ref, ok := refs[m.Name]
		if !ok {
			return errors.New("legacy: assignment order differs")
		}
		u.assignments = append(u.assignments, vault.Assignment{ResourceID: m.Name, CredentialID: ref.CredentialID,
			Fingerprint: ref.Fingerprint, Generation: ref.Generation})
	}
	if len(u.creds) != len(creds) || len(u.assignments) != len(refs) {
		return errors.New("legacy: duplicate member names in credentials.json")
	}
	list, _ := pyjson.Get(doc, "imports")
	items, _ := pyjson.Items(list)
	for _, item := range items {
		if s, ok := pyString(item); ok {
			u.imports = append(u.imports, s)
		} else {
			u.dropped++
		}
	}
	return nil
}

func smbShares(src *Source, userID int64) ([]jsontext.Value, error) {
	doc, found, err := userStore(src, userID, "smb_shares")
	if err != nil || !found {
		return nil, err
	}
	list, err := doc.RawList("smb_shares")
	if err != nil {
		return nil, &StepError{UserID: userID, Record: "smb_shares", Err: err}
	}
	return list, nil
}

// assignmentStatus is the state of each assignment against the given
// records, with saved passwords turned on.
func assignmentStatus(h hosts.Legacy, smb []jsontext.Value, assignments []vault.Assignment) map[string]vault.Status {
	all := vault.ResourcesFromRecords(vault.Records{Profiles: h.Profiles, JumpHosts: h.JumpHosts, SOCKSProxies: h.SOCKSProxies, SMBShares: smb, SMB: true})
	out := map[string]vault.Status{}
	for _, a := range assignments {
		var matches []vault.Resource
		for _, r := range all {
			if r.ID == a.ResourceID {
				matches = append(matches, r)
			}
		}
		switch {
		case len(matches) != 1:
			out[a.ResourceID] = vault.StatusMissing
		case matches[0].Fingerprint != "" && matches[0].Fingerprint == a.Fingerprint:
			out[a.ResourceID] = vault.StatusReady
		default:
			out[a.ResourceID] = vault.StatusChanged
		}
	}
	return out
}

func (s *credentialsStep) Write(ctx context.Context, tx *store.Tx, seal Sealer) error {
	for _, u := range s.users {
		for _, c := range u.creds {
			if err := vault.ImportCredentialTx(ctx, tx, seal, vault.ImportedCredential{UserID: u.id, ID: c.ID, Name: c.Name,
				Username: c.Username, Version: c.Version, UpdatedAt: c.UpdatedAt, Password: []byte(c.Password)}); err != nil {
				return &StepError{UserID: u.id, Record: c.ID, Err: err}
			}
		}
		if err := vault.ImportAssignmentsTx(ctx, tx, u.id, u.assignments, u.imports); err != nil {
			return &StepError{UserID: u.id, Record: "credentials.json", Err: err}
		}
	}
	return nil
}

// Verify opens every stored password and compares it and its metadata
// with the legacy record, compares the assignments and imports, and
// checks that each assignment has the same state against the migrated
// saved hosts, jump hosts and proxies as against the legacy ones: a
// password that worked before still reaches the same target.
func (s *credentialsStep) Verify(ctx context.Context, tx *store.Tx, open Opener) error {
	for _, u := range s.users {
		got, assigns, imports, err := vault.ExportCredentialsTx(ctx, tx, open, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		same := len(got) == len(u.creds)
		for i := 0; same && i < len(got); i++ {
			g, c := got[i], u.creds[i]
			same = g.ID == c.ID && g.Name == c.Name && g.Username == c.Username && g.Version == c.Version &&
				g.UpdatedAt == c.UpdatedAt && bytes.Equal(g.Password, []byte(c.Password))
		}
		for _, g := range got {
			clear(g.Password)
		}
		if !same {
			return &StepError{UserID: u.id, Err: errors.New("legacy: a stored password differs from credentials.json")}
		}
		if !slices.Equal(assigns, u.assignments) || !slices.Equal(imports, u.imports) {
			return &StepError{UserID: u.id, Err: errors.New("legacy: the stored assignments differ from credentials.json")}
		}
		migrated, err := hosts.Export(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		now := assignmentStatus(migrated, u.smb, assigns)
		for id, want := range u.status {
			if now[id] != want {
				return &StepError{UserID: u.id, Record: id, Err: fmt.Errorf("legacy: the assignment is %s after the migration, %s before", now[id], want)}
			}
		}
	}
	return nil
}

func (s *credentialsStep) Report() StepReport {
	r := StepReport{Entity: "E32", Version: 1}
	for _, u := range s.users {
		r.Read += len(u.creds)
		r.Written += len(u.creds)
		for _, a := range u.assignments {
			if st := u.status[a.ResourceID]; st != vault.StatusReady {
				r.Flagged = append(r.Flagged, Flag{UserID: u.id, ID: a.ResourceID, Reason: "assignment_" + string(st)})
			}
		}
		if u.dropped > 0 {
			r.Notes = append(r.Notes, fmt.Sprintf("user %d: %d import entries that are not text were dropped; they could never match a vault", u.id, u.dropped))
		}
	}
	return r
}

// legacyVaultStep migrates entity E30 (D-06): automation-vault.json of
// every account is kept byte for byte in the vault, where the user
// imports it with the passphrase. The migration cannot open it; it checks
// the structure as the import will.
type legacyVaultStep struct {
	users []userVault
}

type userVault struct {
	id       int64
	version  int
	document []byte
}

func (*legacyVaultStep) Entity() string { return "E30" }

func (*legacyVaultStep) Version() int { return 1 }

func (*legacyVaultStep) accountScoped() bool { return true }

func (s *legacyVaultStep) Read(ctx context.Context, src *Source) error {
	rows, err := src.AccountRows(ctx)
	if err != nil {
		return err
	}
	for _, a := range rows {
		v, err := src.Vault(a.ID)
		if err != nil {
			return &StepError{UserID: a.ID, Record: "automation-vault.json", Err: err}
		}
		if v == nil {
			continue
		}
		raw, err := src.readStoreBytes(userDir(a.ID)+"/automation-vault.json", "automation_vault")
		if err != nil {
			return &StepError{UserID: a.ID, Record: "automation-vault.json", Err: err}
		}
		if version, err := vault.CheckLegacyVault(raw); err != nil || version != v.Version {
			return &StepError{UserID: a.ID, Record: "automation-vault.json", Err: errors.New("legacy: the vault cannot be imported")}
		}
		s.users = append(s.users, userVault{id: a.ID, version: v.Version, document: raw})
	}
	return nil
}

func (s *legacyVaultStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	for _, u := range s.users {
		if err := vault.ImportLegacyVaultTx(ctx, tx, u.id, u.document, u.version); err != nil {
			return &StepError{UserID: u.id, Record: "automation-vault.json", Err: err}
		}
	}
	return nil
}

// Verify reads every kept vault back byte for byte and checks it once
// more as the import will.
func (s *legacyVaultStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	for _, u := range s.users {
		doc, version, found, err := vault.ExportLegacyVaultTx(ctx, tx, u.id)
		if err != nil {
			return &StepError{UserID: u.id, Err: err}
		}
		if _, cerr := vault.CheckLegacyVault(doc); !found || version != u.version || !bytes.Equal(doc, u.document) || cerr != nil {
			return &StepError{UserID: u.id, Record: "automation-vault.json", Err: errors.New("legacy: the kept vault differs")}
		}
	}
	return nil
}

func (s *legacyVaultStep) Report() StepReport {
	r := StepReport{Entity: "E30", Version: 1}
	for _, u := range s.users {
		r.Read++
		r.Written++
		r.UserActions = append(r.UserActions, UserAction{UserID: u.id, Action: "import_legacy_automation_vault"})
	}
	if len(s.users) > 0 {
		r.Notes = append(r.Notes, "legacy automation vaults are kept unchanged; each user imports theirs on the Passwords page with its passphrase")
	}
	return r
}

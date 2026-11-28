package automation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
	"github.com/bifrost0x/webssh/internal/vault"
)

func (s *Service) runbooks(ctx context.Context, userID int64) ([]Runbook, error) {
	var books []Runbook
	err := s.o.DB.Read(ctx, func(tx *store.Tx) error {
		var err error
		books, err = readRunbooks(ctx, tx, userID)
		return err
	})
	return books, storageErr(err)
}

func (s *Service) runbook(ctx context.Context, userID int64, id string) (Runbook, error) {
	books, err := s.runbooks(ctx, userID)
	if err != nil {
		return Runbook{}, err
	}
	i := slices.IndexFunc(books, func(b Runbook) bool { return b.ID == id })
	if i < 0 {
		return Runbook{}, Fail("not_found")
	}
	return books[i], nil
}

// storageErr turns a store failure into storage_unavailable; automation
// errors pass.
func storageErr(err error) error {
	if err == nil || Code(err) != "" {
		return err
	}
	return &storageError{err}
}

type storageError struct{ err error }

func (e *storageError) Error() string { return "automation: storage: " + e.err.Error() }
func (e *storageError) Unwrap() error { return e.err }

func (s *Service) inventory(ctx context.Context, userID int64) (inventory, error) {
	r, err := s.o.Records.Records(ctx, userID)
	if err != nil {
		return inventory{}, storageErr(err)
	}
	return newInventory(r), nil
}

// Freeze is the review of a run without the intent: the runbook, the
// selected targets with their jump hosts, a trusted host key for every
// hop, the saved passwords bound and the keys readable. Schedules (AU2)
// review the same way.
func (s *Service) Freeze(ctx context.Context, userID int64, runbookID string, profileIDs, groups []string) (Reviewed, error) {
	book, err := s.runbook(ctx, userID, runbookID)
	if err != nil {
		return Reviewed{}, err
	}
	inv, err := s.inventory(ctx, userID)
	if err != nil {
		return Reviewed{}, err
	}
	targets, err := inv.freeze(selection{ProfileIDs: profileIDs, Groups: groups})
	if err != nil {
		return Reviewed{}, err
	}
	if err := s.requireTrust(ctx, userID, targets); err != nil {
		return Reviewed{}, err
	}
	bindings, err := s.bindings(ctx, userID, targets, true)
	if err != nil {
		return Reviewed{}, err
	}
	digests, err := s.keyDigests(ctx, userID, targets)
	if err != nil {
		return Reviewed{}, err
	}
	return Reviewed{Runbook: book, Targets: targets, KeyDigests: digests, Bindings: bindings}, nil
}

// Reviewed is a reviewed run: what the user confirmed.
type Reviewed struct {
	Runbook    Runbook
	Targets    []Frozen
	KeyDigests map[string]string
	Bindings   map[string]string
}

// requireTrust is _require_trusted_host_keys: the review fails early,
// naming the saved hosts whose key the user still has to verify in an
// interactive connection.
func (s *Service) requireTrust(ctx context.Context, userID int64, targets []Frozen) error {
	var missing []string
	for _, h := range hops(targets) {
		ok, err := s.o.HostTrust.Trusted(ctx, userID, h.Host, int(h.Port))
		if err != nil {
			if fault.Is(err, fault.InvalidValue) || fault.Is(err, fault.InvalidRequest) {
				return Fail("invalid_targets")
			}
			return storageErr(err)
		}
		if !ok {
			missing = append(missing, h.Name)
		}
	}
	if len(missing) > 0 {
		return &Error{Code: "host_key_required", Hosts: missing[:min(len(missing), 50)]}
	}
	return nil
}

// passwordCode maps the state of a saved password to the error of the
// review or the run.
func passwordCode(st vault.Status) string {
	switch st {
	case vault.StatusChanged:
		return "credential_target_changed"
	case vault.StatusDisabled:
		return "credentials_disabled"
	}
	return "credential_missing"
}

func faultCode(err error) string {
	if c := Code(err); c != "" {
		return c
	}
	for _, c := range []fault.Code{fault.CredentialMissing, fault.CredentialTargetChanged, fault.CredentialsDisabled,
		fault.CredentialUnreadable, fault.CredentialUnavailable} {
		if fault.Is(err, c) {
			return string(c)
		}
	}
	return ""
}

// bindings returns the binding of every password hop; read also opens
// each password once, as the Python review did, so an unreadable one
// fails the review instead of the run.
func (s *Service) bindings(ctx context.Context, userID int64, targets []Frozen, read bool) (map[string]string, error) {
	out := map[string]string{}
	for _, h := range hops(targets) {
		if h.AuthType != "password" {
			continue
		}
		st, token, err := s.o.Passwords.Binding(ctx, userID, h.ResourceID, h.Target)
		if err != nil {
			if c := faultCode(err); c != "" {
				return nil, Fail(c)
			}
			return nil, storageErr(err)
		}
		if st != vault.StatusReady {
			return nil, Fail(passwordCode(st))
		}
		if read {
			secret, err := s.o.Passwords.Password(ctx, userID, h.ResourceID, h.Target)
			clear(secret)
			if err != nil {
				if c := faultCode(err); c != "" {
					return nil, Fail(c)
				}
				return nil, storageErr(err)
			}
		}
		out[h.ResourceID] = token
	}
	return out, nil
}

// keyDigests binds every key hop to its stored key: replacing the key
// after the review changes the digest.
func (s *Service) keyDigests(ctx context.Context, userID int64, targets []Frozen) (map[string]string, error) {
	out := map[string]string{}
	for _, h := range hops(targets) {
		if h.AuthType != "key" {
			continue
		}
		public, err := s.o.Keys.PublicKey(ctx, userID, h.KeyID)
		if fault.Is(err, fault.StorageError) {
			return nil, storageErr(err)
		}
		if err != nil || h.KeyID == "" || len(public) == 0 {
			return nil, Fail("key_unavailable")
		}
		sum := sha256.Sum256(public)
		out[h.ResourceID] = hex.EncodeToString(sum[:])
	}
	return out, nil
}

// validate is validate_run: the runbook, every target as reviewed (its
// fingerprint covers its jump host), the keys and the saved passwords.
func (s *Service) validate(ctx context.Context, userID int64, f Reviewed) error {
	if err := s.enabledSwitch(ctx); err != nil {
		return err
	}
	book, err := s.runbook(ctx, userID, f.Runbook.ID)
	if err != nil || !book.equal(f.Runbook) {
		return Fail("preview_changed")
	}
	inv, err := s.inventory(ctx, userID)
	if err != nil {
		return err
	}
	for _, t := range f.Targets {
		cur, ok := inv.byID(t.ResourceID)
		if !ok || cur.Fingerprint == "" || cur.Fingerprint != t.Fingerprint {
			return Fail("preview_changed")
		}
	}
	digests, err := s.keyDigests(ctx, userID, f.Targets)
	if err != nil {
		return err
	}
	if !maps.Equal(digests, f.KeyDigests) {
		return Fail("preview_changed")
	}
	bindings, err := s.bindings(ctx, userID, f.Targets, false)
	if err != nil {
		return err
	}
	if !maps.Equal(bindings, f.Bindings) {
		return Fail("preview_changed")
	}
	return nil
}

func (s *Service) enabledSwitch(ctx context.Context) error {
	on, err := s.o.Switches.AutomationEnabled(ctx)
	if err != nil || !on || !s.o.Accepting() {
		return Fail("preview_changed")
	}
	return nil
}

// Preview is prepare_run for the signed-in user.
func (s *Service) Preview(ctx context.Context, userID int64, sessionID string, body jsontext.Value) (jsontext.Value, error) {
	idV, _ := pyjson.Get(body, "runbook_id")
	id, _ := pyString(idV)
	sel, err := parseSelection(body)
	if err != nil {
		return nil, err
	}
	f, err := s.Freeze(ctx, userID, id, sel.ProfileIDs, sel.Groups)
	if err != nil {
		return nil, err
	}
	return s.remember(&review{userID: userID, sessionID: sessionID, book: f.Runbook, targets: f.Targets,
		keyDigests: f.KeyDigests, bindings: f.Bindings})
}

// remember registers a review and returns the answer of preview-run:
// intent, runbook, targets, confirmation and expires_in.
func (s *Service) remember(r *review) (jsontext.Value, error) {
	token, err := s.intents.remember(r, s.o.Now())
	if err != nil {
		return nil, err
	}
	targets := make([]jsontext.Value, len(r.targets))
	for i, t := range r.targets {
		targets[i] = pyjson.Object(t.display())
	}
	return pyjson.Object([]pyjson.Member{
		{Name: "intent", Value: pyjson.String(token)},
		{Name: "runbook", Value: r.book.Value()},
		{Name: "targets", Value: pyjson.Array(targets)},
		{Name: "confirmation", Value: pyjson.String(r.confirmation())},
		{Name: "expires_in", Value: jsontext.Value("300")},
	}), nil
}

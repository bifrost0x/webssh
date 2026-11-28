package vault

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"uuid"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Limits bound each user's key store (SSH_KEY_MAX_RECORDS and
// SSH_KEY_STORE_MAX_BYTES). Stores above the byte limit stay usable: keys
// can be renamed, deleted or replaced by smaller ones; only growth is
// refused, as in the Python release.
type Limits struct {
	MaxRecords    int
	MaxStoreBytes int64
}

// Options configures a Service. Every field except Now is required.
type Options struct {
	DB     *store.DB
	Sealer Sealer
	StepUp StepUp
	Limits Limits
	// Now is the clock for uploaded_at (default time.Now).
	Now func() time.Time
}

// kdfSlots bounds how many passphrase-protected keys are opened at the
// same time across all users; each one costs CPU for its KDF. One user
// holds at most one slot, so a single account cannot take them all.
const kdfSlots = 2

// Service manages the users' SSH keys and provides client.KeySource.
type Service struct {
	db     *store.DB
	sealer Sealer
	stepUp StepUp
	limits Limits
	now    func() time.Time
	kdf    chan struct{}

	mu      sync.Mutex
	kdfUser map[int64]bool // users holding a KDF slot

	creds *credentials // saved passwords; nil until EnableCredentials
	pub   publicKeys   // public keys of opened sealed keys
}

// New returns a Service.
func New(o Options) (*Service, error) {
	if o.DB == nil || o.Sealer == nil || o.StepUp == nil || o.Limits.MaxRecords <= 0 || o.Limits.MaxStoreBytes <= 0 {
		return nil, errors.New("vault: incomplete options")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{db: o.DB, sealer: o.Sealer, stepUp: o.StepUp, limits: o.Limits, now: o.Now, kdf: make(chan struct{}, kdfSlots), kdfUser: map[int64]bool{}}, nil
}

// Summary is the key as the page sees it; it never holds key material.
type Summary struct {
	ID         string
	Name       string
	KeyType    string
	UploadedAt string
	Usable     bool
}

// List returns the caller's keys in their stored order. A key is usable
// when WebSSH can load it and its sealed value opens.
func (s *Service) List(ctx context.Context) ([]Summary, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return nil, err
	}
	var rows []keyRow
	if err := s.db.Read(ctx, func(tx *store.Tx) error {
		rows, err = listRows(ctx, tx, p.UserID)
		return err
	}); err != nil {
		return nil, storage(err)
	}
	out := make([]Summary, 0, len(rows))
	for _, r := range rows {
		out = append(out, s.summary(r))
	}
	return out, nil
}

func (s *Service) summary(r keyRow) Summary {
	usable := false
	if r.State == stateUsable {
		if plain, err := s.sealer.Open(keyring.SSHKey, aad(r.UserID, r.ID), r.Sealed); err == nil {
			clear(plain)
			usable = true
		}
	}
	return Summary{ID: r.ID, Name: r.Name, KeyType: r.KeyType, UploadedAt: r.UploadedAt, Usable: usable}
}

// Upload is a new key. Passphrase opens a protected key; it is not stored.
type Upload struct {
	Name, Content, Passphrase, Grant string
}

// Upload stores a new key after a step-up for key.upload, bound to the
// user. The key is checked first, so a missing passphrase does not spend
// the grant.
func (s *Service) Upload(ctx context.Context, u Upload) (Summary, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return Summary{}, err
	}
	if u.Name == "" || u.Content == "" {
		return Summary{}, invalid(textNameContentRequired)
	}
	if strings.TrimSpace(u.Name) == "" {
		return Summary{}, invalid(textInvalidName)
	}
	if utf8.RuneCountInString(u.Name) > MaxNameRunes {
		return Summary{}, invalid(textNameTooLong)
	}
	key, err := s.parse(p.UserID, u.Content, u.Passphrase)
	if err != nil {
		return Summary{}, err
	}
	r := keyRow{ID: uuid.NewV4().String(), UserID: p.UserID, Name: u.Name, UploadedAt: isoTime(s.now())}
	if err := s.fill(&r, key); err != nil {
		return Summary{}, err
	}
	grow := func(tx *store.Tx) error {
		count, size, err := usage(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		if count >= int64(s.limits.MaxRecords) || size+int64(len(r.Sealed)) > s.limits.MaxStoreBytes {
			return storageLimit()
		}
		return nil
	}
	if err := s.db.Read(ctx, grow); err != nil {
		return Summary{}, storage(err)
	}
	if err := s.stepUp.Consume(ctx, p, principal.ActionKeyUpload, userTarget(p), u.Grant); err != nil {
		return Summary{}, err
	}
	if err := s.db.Write(ctx, func(tx *store.Tx) error {
		if err := grow(tx); err != nil {
			return err
		}
		return insertRow(ctx, tx, r)
	}); err != nil {
		return Summary{}, storage(err)
	}
	return Summary{ID: r.ID, Name: r.Name, KeyType: r.KeyType, UploadedAt: r.UploadedAt, Usable: true}, nil
}

// Rename changes a key's name; it needs no step-up (D-21 covers only the
// key material).
func (s *Service) Rename(ctx context.Context, id, name string) (Summary, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return Summary{}, err
	}
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return Summary{}, invalid(textInvalidName)
	case utf8.RuneCountInString(name) > MaxNameRunes:
		return Summary{}, invalid(textNameTooLong)
	case id == "":
		return Summary{}, notFound()
	}
	var r keyRow
	if err := s.db.Write(ctx, func(tx *store.Tx) error {
		if err := renameRow(ctx, tx, p.UserID, id, name); err != nil {
			return err
		}
		var found bool
		r, found, err = getRow(ctx, tx, p.UserID, id)
		if !found && err == nil {
			err = errNotFound
		}
		return err
	}); err != nil {
		return Summary{}, storage(err)
	}
	return s.summary(r), nil
}

// Replace swaps the key material of a key and keeps its ID, name and
// upload time, after a step-up for key.replace bound to the key ID. The
// replacement must be of the same key type.
type Replace struct {
	ID, Content, Passphrase, Grant string
}

// Replace implements key replacement.
func (s *Service) Replace(ctx context.Context, rq Replace) (Summary, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return Summary{}, err
	}
	if rq.ID == "" || rq.Content == "" {
		return Summary{}, invalid(textIDContentRequired)
	}
	if !validID(rq.ID) {
		return Summary{}, notFound()
	}
	key, err := s.parse(p.UserID, rq.Content, rq.Passphrase)
	if err != nil {
		return Summary{}, err
	}
	next := keyRow{ID: rq.ID, UserID: p.UserID}
	if err := s.fill(&next, key); err != nil {
		return Summary{}, err
	}
	var current keyRow
	check := func(tx *store.Tx) error {
		r, found, err := getRow(ctx, tx, p.UserID, rq.ID)
		switch {
		case err != nil:
			return err
		case !found:
			return errNotFound
		case r.KeyType != next.KeyType:
			return typeMismatch(r.KeyType)
		}
		_, size, err := usage(ctx, tx, p.UserID)
		if err != nil {
			return err
		}
		after := size - int64(len(r.Sealed)) + int64(len(next.Sealed))
		if after > s.limits.MaxStoreBytes && after > size {
			return storageLimit()
		}
		current = r
		return nil
	}
	if err := s.db.Read(ctx, check); err != nil {
		return Summary{}, storage(err)
	}
	if err := s.stepUp.Consume(ctx, p, principal.ActionKeyReplace, rq.ID, rq.Grant); err != nil {
		return Summary{}, err
	}
	if err := s.db.Write(ctx, func(tx *store.Tx) error {
		if err := check(tx); err != nil {
			return err
		}
		return replaceRow(ctx, tx, next)
	}); err != nil {
		return Summary{}, storage(err)
	}
	return Summary{ID: current.ID, Name: current.Name, KeyType: next.KeyType, UploadedAt: current.UploadedAt, Usable: true}, nil
}

// Delete removes a key after a step-up for key.delete bound to its ID.
// Profiles and jump hosts that name it then show it as missing, as in the
// Python release.
func (s *Service) Delete(ctx context.Context, id, grant string) error {
	p, err := principal.Require(ctx)
	if err != nil {
		return err
	}
	if id == "" {
		return invalid(textIDRequired)
	}
	exists := func(tx *store.Tx) error {
		_, found, err := getRow(ctx, tx, p.UserID, id)
		if err == nil && !found {
			err = errNotFound
		}
		return err
	}
	if err := s.db.Read(ctx, exists); err != nil {
		return storage(err)
	}
	if err := s.stepUp.Consume(ctx, p, principal.ActionKeyDelete, id, grant); err != nil {
		return err
	}
	if err := s.db.Write(ctx, func(tx *store.Tx) error { return deleteRow(ctx, tx, p.UserID, id) }); err != nil {
		return storage(err)
	}
	return nil
}

// Signer implements client.KeySource: it opens the owner's key for one
// connection.
func (s *Service) Signer(ctx context.Context, owner int64, keyID string) (ssh.Signer, error) {
	r, err := s.usableRow(ctx, owner, keyID)
	if err != nil {
		return nil, err
	}
	return s.openKey(owner, keyID, r)
}

// usableRow reads the owner's key and refuses one WebSSH cannot use.
func (s *Service) usableRow(ctx context.Context, owner int64, keyID string) (keyRow, error) {
	var (
		r     keyRow
		found bool
	)
	if err := s.db.Read(ctx, func(tx *store.Tx) (err error) {
		r, found, err = getRow(ctx, tx, owner, keyID)
		return err
	}); err != nil {
		return keyRow{}, storage(err)
	}
	if !found {
		return keyRow{}, notFound()
	}
	if r.State != stateUsable {
		return keyRow{}, fault.New(fault.InvalidValue, textUnusable)
	}
	return r, nil
}

// openKey opens the sealed key of r and parses it.
func (s *Service) openKey(owner int64, keyID string, r keyRow) (ssh.Signer, error) {
	plain, err := s.sealer.Open(keyring.SSHKey, aad(owner, keyID), r.Sealed)
	if err != nil {
		return nil, fault.Wrap(fault.InvalidValue, err, textUnusable)
	}
	defer clear(plain)
	signer, _, err := signerOf(plain)
	if err != nil {
		return nil, fault.Wrap(fault.InvalidValue, err, textUnusable)
	}
	return signer, nil
}

// HasKey implements hosts.Keys: it reports whether owner has a stored key
// with this ID, usable or not, so a saved host can refer to it as the
// Python release allowed.
func (s *Service) HasKey(ctx context.Context, owner int64, keyID string) (bool, error) {
	var found bool
	if err := s.db.Read(ctx, func(tx *store.Tx) (err error) {
		_, found, err = getRow(ctx, tx, owner, keyID)
		return err
	}); err != nil {
		return false, storage(err)
	}
	return found, nil
}

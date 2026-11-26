package vault

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
// same time across all users; each one costs CPU for its KDF.
const kdfSlots = 2

// Service manages the users' SSH keys and provides client.KeySource.
type Service struct {
	db     *store.DB
	sealer Sealer
	stepUp StepUp
	limits Limits
	now    func() time.Time
	kdf    chan struct{}
}

// New returns a Service.
func New(o Options) (*Service, error) {
	if o.DB == nil || o.Sealer == nil || o.StepUp == nil || o.Limits.MaxRecords <= 0 || o.Limits.MaxStoreBytes <= 0 {
		return nil, errors.New("vault: incomplete options")
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return &Service{db: o.DB, sealer: o.Sealer, stepUp: o.StepUp, limits: o.Limits, now: o.Now, kdf: make(chan struct{}, kdfSlots)}, nil
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
	key, err := s.parse(u.Content, u.Passphrase)
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
	key, err := s.parse(rq.Content, rq.Passphrase)
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
	var (
		r     keyRow
		found bool
	)
	if err := s.db.Read(ctx, func(tx *store.Tx) (err error) {
		r, found, err = getRow(ctx, tx, owner, keyID)
		return err
	}); err != nil {
		return nil, storage(err)
	}
	if !found {
		return nil, notFound()
	}
	if r.State != stateUsable {
		return nil, fault.New(fault.InvalidValue, textUnusable)
	}
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

// parse checks an uploaded key. Opening a passphrase-protected key takes
// one of the KDF slots; when all are taken the caller retries.
func (s *Service) parse(content, passphrase string) (parsedKey, error) {
	if len(content) > MaxKeyBytes {
		return parsedKey{}, invalid(textContentTooLarge)
	}
	if len(passphrase) > MaxPassphraseBytes {
		return parsedKey{}, invalid(textPassphraseTooLong)
	}
	if passphrase != "" {
		select {
		case s.kdf <- struct{}{}:
			defer func() { <-s.kdf }()
		default:
			e := fault.New(fault.Busy, textBusy)
			e.RetryAfter = time.Second
			return parsedKey{}, e
		}
	}
	pass := []byte(passphrase)
	defer clear(pass)
	key, err := parseKey([]byte(content), pass)
	if err != nil {
		return parsedKey{}, keyFault(err)
	}
	return key, nil
}

// fill seals the parsed key into r and sets its public facts.
func (s *Service) fill(r *keyRow, key parsedKey) error {
	defer clear(key.stored)
	sealed, err := s.sealer.Seal(keyring.SSHKey, aad(r.UserID, r.ID), key.stored)
	if err != nil {
		return fault.Wrap(fault.StorageError, fmt.Errorf("vault: seal key: %w", err), "")
	}
	pub := key.signer.PublicKey()
	r.KeyType = key.keyType
	r.PublicKey = strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	r.Fingerprint = ssh.FingerprintSHA256(pub)
	r.Sealed = sealed
	r.State = stateUsable
	return nil
}

// userTarget is the step-up target of key.upload: the user ID, the
// default target of the account step-up intents.
func userTarget(p principal.Principal) string { return strconv.FormatInt(p.UserID, 10) }

// isoTime renders t like Python's datetime.isoformat() for an aware UTC
// datetime: microseconds only when not zero. The Python release wrote
// naive UTC times, which the page showed as local time; new keys carry the
// offset.
func isoTime(t time.Time) string {
	t = t.UTC()
	s := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	return s + "+00:00"
}

package vault

import (
	"context"
	"errors"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/store"
)

// Policy is the administrator switch of saved passwords and its revision
// (credentials_enabled and credentials_enabled_revision of the
// application settings). A new revision ends every prepared intent,
// authorized target and binding assurance.
type Policy interface {
	CredentialsPolicy(ctx context.Context) (enabled bool, revision string, err error)
}

// Incarnations returns the incarnation of an account (the creation time
// as the Python release wrote it), which binds the legacy automation vault
// to the account (provided by internal/accounts).
type Incarnations interface {
	Incarnation(ctx context.Context, userID int64) (string, error)
}

// Audit records security events of saved passwords; it never receives a
// secret.
type Audit interface {
	CredentialChanged(ctx context.Context, userID int64, action string)
}

// CredentialOptions are the dependencies of saved passwords. Stores,
// Policy and Accounts are required; Writer enables creating a resource
// together with its password, Audit the security events.
type CredentialOptions struct {
	Stores   Stores
	Writer   ResourceWriter
	Policy   Policy
	Accounts Incarnations
	Audit    Audit
}

// credentials is the saved-password part of the Service.
type credentials struct {
	CredentialOptions
	intents *intents
	kdf     chan struct{}
}

// errNoCredentials is returned while saved passwords are not configured.
var errNoCredentials = fault.New(fault.Unavailable, "")

// EnableCredentials turns on saved passwords. It is called once while the
// server is wired, before any request.
func (s *Service) EnableCredentials(o CredentialOptions) error {
	if o.Stores == nil || o.Policy == nil || o.Accounts == nil {
		return errors.New("vault: incomplete credential options")
	}
	s.creds = &credentials{CredentialOptions: o, intents: newIntents(s.now), kdf: make(chan struct{}, 1)}
	return nil
}

func (s *Service) credentials() (*credentials, error) {
	if s.creds == nil {
		return nil, errNoCredentials
	}
	return s.creds, nil
}

// policy returns the switch and its revision. Unless erase is set a
// disabled switch is credentials_disabled; erasing stays possible so users
// can delete what they saved.
func (c *credentials) policy(ctx context.Context, erase bool) (enabled bool, revision string, err error) {
	enabled, revision, err = c.Policy.CredentialsPolicy(ctx)
	if err != nil {
		return false, "", fault.Wrap(fault.StorageError, err, "")
	}
	if !enabled && !erase {
		return false, revision, fault.New(fault.CredentialsDisabled, "")
	}
	return enabled, revision, nil
}

func (c *credentials) audit(ctx context.Context, userID int64, action string) {
	if c.Audit != nil {
		c.Audit.CredentialChanged(ctx, userID, action)
	}
}

// resources returns the user's resources.
func (c *credentials) resources(ctx context.Context, userID int64) ([]Resource, bool, error) {
	r, err := c.Stores.Records(ctx, userID)
	if err != nil {
		return nil, false, fault.Wrap(fault.StorageError, err, "")
	}
	return ResourcesFromRecords(r), r.SMB, nil
}

// resolve is resolve_resource: exactly one resource with the id, else
// invalid_targets (legacy stores may hold duplicate ids, and list order
// must never pick another resource's binding).
func resolve(all []Resource, id string) (Resource, error) {
	if !validText(id, 128, false) {
		return Resource{}, fault.New(fault.InvalidRequest, "")
	}
	var found []Resource
	for _, r := range all {
		if r.ID == id {
			found = append(found, r)
		}
	}
	if len(found) != 1 {
		return Resource{}, fault.New(fault.InvalidTargets, "")
	}
	return found[0], nil
}

// Resource returns the current target of a resource of the user; it
// implements Resources for the consumers of saved passwords.
func (s *Service) Resource(ctx context.Context, userID int64, resourceID string) (Target, bool, error) {
	c, err := s.credentials()
	if err != nil {
		return Target{}, false, err
	}
	all, _, err := c.resources(ctx, userID)
	if err != nil {
		return Target{}, false, err
	}
	r, err := resolve(all, resourceID)
	if err != nil {
		return Target{}, false, nil //nolint:nilerr // an unknown or ambiguous id is not found
	}
	return r.Target, true, nil
}

// readDoc loads the user's document in a read transaction.
func (s *Service) readDoc(ctx context.Context, userID int64) (*credDoc, error) {
	var d *credDoc
	err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		d, err = loadDoc(ctx, tx, userID)
		return err
	})
	if err != nil {
		return nil, storage(err)
	}
	return d, nil
}

// mutate runs op on the user's document and writes it back in one write
// transaction; an error of op writes nothing.
func (s *Service) mutate(ctx context.Context, userID int64, op func(tx *store.Tx, d *credDoc) error) error {
	err := s.db.Write(ctx, func(tx *store.Tx) error {
		d, err := loadDoc(ctx, tx, userID)
		if err != nil {
			return err
		}
		if err := op(tx, d); err != nil {
			return err
		}
		return saveDoc(ctx, tx, userID, d)
	})
	if err != nil {
		return storage(err)
	}
	return nil
}

// newCredential seals a new password record. The secret is cleared.
func (s *Service) newCredential(userID int64, name, username string, secret []byte) (credRow, error) {
	c := credRow{ID: randomHex(16), Name: name, Username: username, Version: randomHex(32), UpdatedAt: pyISOTime(s.now())}
	sealed, err := s.sealSecret(userID, c.ID, secret)
	if err != nil {
		return credRow{}, err
	}
	c.Secret = sealed
	return c, nil
}

// sealSecret seals a password for the record id of a user and clears it.
func (s *Service) sealSecret(userID int64, id string, secret []byte) ([]byte, error) {
	defer clear(secret)
	sealed, err := s.sealer.Seal(keyring.Credential, credentialAAD(userID, id), secret)
	if err != nil {
		return nil, fault.Wrap(fault.StorageError, err, "")
	}
	return sealed, nil
}

// open returns the plaintext of a record; the caller clears it.
func (s *Service) open(userID int64, c *credRow) ([]byte, error) {
	plain, err := s.sealer.Open(keyring.Credential, credentialAAD(userID, c.ID), c.Secret)
	if err != nil {
		return nil, fault.New(fault.CredentialUnreadable, "")
	}
	return plain, nil
}

// Revoke ends the prepared operations and the binding assurance of a
// user, for example after the account's sessions were revoked.
func (s *Service) Revoke(userID int64) {
	if s.creds != nil {
		s.creds.intents.revokeUser(userID)
	}
}

// Sweep drops expired intents; the server calls it periodically.
func (s *Service) Sweep() {
	if s.creds != nil {
		s.creds.intents.sweep()
	}
}

// SweepInterval is how often the server calls Sweep.
const SweepInterval = 5 * time.Second

func requireUser(ctx context.Context) (principal.Principal, error) {
	return principal.Require(ctx)
}

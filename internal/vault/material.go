package vault

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/principal"
)

// parse checks an uploaded key. Opening a passphrase-protected key takes
// one of the KDF slots; when none is free, or the user already holds one,
// the caller retries.
func (s *Service) parse(userID int64, content, passphrase string) (parsedKey, error) {
	if len(content) > MaxKeyBytes {
		return parsedKey{}, invalid(textContentTooLarge)
	}
	if len(passphrase) > MaxPassphraseBytes {
		return parsedKey{}, invalid(textPassphraseTooLong)
	}
	if passphrase != "" {
		release, ok := s.takeKDFSlot(userID)
		if !ok {
			e := fault.New(fault.Busy, textBusy)
			e.RetryAfter = time.Second
			return parsedKey{}, e
		}
		defer release()
	}
	raw, pass := []byte(content), []byte(passphrase)
	defer clear(pass)
	key, err := parseKey(raw, pass)
	// The copy of the upload becomes the stored form only for a key
	// without passphrase; fill clears it then.
	if err != nil || len(key.stored) == 0 || &key.stored[0] != &raw[0] {
		clear(raw)
	}
	if err != nil {
		return parsedKey{}, keyFault(err)
	}
	return key, nil
}

func (s *Service) takeKDFSlot(userID int64) (release func(), ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.kdfUser[userID] {
		return nil, false
	}
	select {
	case s.kdf <- struct{}{}:
	default:
		return nil, false
	}
	s.kdfUser[userID] = true
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		delete(s.kdfUser, userID)
		<-s.kdf
	}, true
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

// validID reports whether id can name a stored key: IDs are UUIDs, or
// whatever the Python release wrote, which never held control characters.
func validID(id string) bool {
	return id != "" && len(id) <= 128 && utf8.ValidString(id) && !strings.ContainsFunc(id, unicode.IsControl)
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

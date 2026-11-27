package vault

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// Parameters of automation-vault.json (app/automation_vault.py).
const (
	legacyN        = 131072
	legacyR        = 8
	legacyP        = 1
	legacySaltSize = 16
	legacyMaxRec   = 100
)

// legacyEnvelope is a checked automation-vault.json.
type legacyEnvelope struct {
	version           int
	salt, nonce, data []byte
}

// parseLegacyVault applies _valid and _decode of automation_vault.py. A
// document that does not pass is vault_unreadable.
func parseLegacyVault(document []byte) (legacyEnvelope, error) {
	unreadable := fault.New(fault.VaultUnreadable, "")
	doc, _, err := pyjson.Load(document)
	if err != nil {
		return legacyEnvelope{}, unreadable
	}
	members, ok := pyjson.Members(doc)
	if !ok || len(members) != 5 {
		return legacyEnvelope{}, unreadable
	}
	var e legacyEnvelope
	get := func(name string) jsontext.Value { v, _ := pyjson.Get(doc, name); return v }
	switch string(get("version")) {
	case "1":
		e.version = 1
	case "2":
		e.version = 2
	default:
		return legacyEnvelope{}, unreadable
	}
	if kdf, ok := asString(get("kdf")); !ok || kdf != LegacyKDF {
		return legacyEnvelope{}, unreadable
	}
	for _, f := range []struct {
		dst  *[]byte
		name string
		max  int
	}{{&e.salt, "salt", 32}, {&e.nonce, "nonce", 32}, {&e.data, "ciphertext", 900000}} {
		text, ok := asString(get(f.name))
		if !ok || utf8.RuneCountInString(text) > f.max {
			return legacyEnvelope{}, unreadable
		}
		if *f.dst, err = base64.StdEncoding.Strict().DecodeString(text); err != nil {
			return legacyEnvelope{}, unreadable
		}
	}
	if len(e.nonce) != 12 {
		return legacyEnvelope{}, unreadable
	}
	return e, nil
}

// legacyRecord is one decrypted vault entry, keyed by resource id.
type legacyRecord struct {
	ResourceID  string
	Fingerprint string
	Password    string
}

// openLegacyVault decrypts a vault with the user's passphrase. The AES-GCM
// additional data binds it to the account: version, user id and
// incarnation.
func openLegacyVault(e legacyEnvelope, userID int64, incarnation, passphrase string) ([]legacyRecord, error) {
	if !validText(passphrase, LegacyMaxPassByte, false) {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	if utf8.RuneCountInString(passphrase) < LegacyMinPassRune || len(e.salt) != legacySaltSize {
		return nil, fault.New(fault.InvalidPassphrase, "")
	}
	key, err := scrypt.Key([]byte(passphrase), e.salt, legacyN, legacyR, legacyP, 32)
	if err != nil {
		return nil, fault.Wrap(fault.Internal, err, "")
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fault.Wrap(fault.Internal, err, "")
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fault.Wrap(fault.Internal, err, "")
	}
	aad := fmt.Sprintf("webssh-automation-vault-v%d:%d:%s", e.version, userID, incarnation)
	plain, err := gcm.Open(nil, e.nonce, e.data, []byte(aad))
	if err != nil {
		return nil, fault.New(fault.VaultUnlockFailed, "")
	}
	defer clear(plain)
	return parseLegacyRecords(plain, e.version)
}

// parseLegacyRecords applies the record checks of _decrypt in the order of
// the document. Python reported a plaintext that is not JSON as a failed
// unlock and a wrong shape as unreadable.
func parseLegacyRecords(plain []byte, version int) ([]legacyRecord, error) {
	doc, _, err := pyjson.Load(plain)
	if err != nil {
		return nil, fault.New(fault.VaultUnlockFailed, "")
	}
	members, ok := pyjson.Members(doc)
	unreadable := fault.New(fault.VaultUnreadable, "")
	if !ok || len(members) > legacyMaxRec {
		return nil, unreadable
	}
	want := []string{"fingerprint", "password"}
	if version == 2 {
		want = []string{"fingerprint", "generation", "password"}
	}
	out := make([]legacyRecord, 0, len(members))
	for _, m := range members {
		fields, ok := pyjson.Members(m.Value)
		names := make([]string, 0, len(fields))
		for _, f := range fields {
			names = append(names, f.Name)
		}
		slices.Sort(names)
		if !ok || !slices.Equal(names, want) {
			return nil, unreadable
		}
		get := func(name string) jsontext.Value { v, _ := pyjson.Get(m.Value, name); return v }
		fp, okF := asString(get("fingerprint"))
		pw, okP := asString(get("password"))
		if !okF || !okP || utf8.RuneCountInString(fp) != 64 || pw == "" || len(pw) > MaxSecretBytes {
			return nil, unreadable
		}
		if version == 2 {
			gen, ok := asString(get("generation"))
			if !ok || !isLowerHex64(gen) {
				return nil, unreadable
			}
		}
		out = append(out, legacyRecord{ResourceID: m.Name, Fingerprint: fp, Password: pw})
	}
	return out, nil
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// ImportLegacy imports the legacy automation vault of the signed-in user
// with the passphrase it was created with, after a step-up for
// credentials.vault bound to grant (or a recent one of the session). It
// returns the number of passwords created; a document imported before
// creates none.
func (s *Service) ImportLegacy(ctx context.Context, p principal.Principal, passphrase []byte, grant string) (int, error) {
	c, err := s.credentials()
	if err != nil {
		return 0, err
	}
	_, revision, err := c.policy(ctx, false)
	if err != nil {
		return 0, err
	}
	if !c.intents.assured(p, revision) {
		if err := s.stepUp.Consume(ctx, p, principal.ActionCredentialsVault, "import-legacy", grant); err != nil {
			return 0, err
		}
		c.intents.assure(p, revision)
	}
	return s.importLegacy(ctx, c, p.UserID, pyjson.String(string(passphrase)))
}

// importLegacy creates one password per vault record, named after its
// resource (else its id, else "Imported password"), and assigns it where
// the resource exists and has no assignment, keeping the fingerprint the
// record was bound to. A wrong passphrase changes nothing.
func (s *Service) importLegacy(ctx context.Context, c *credentials, userID int64, passV jsontext.Value) (int, error) {
	if _, _, err := c.policy(ctx, false); err != nil {
		return 0, err
	}
	var stored legacyVault
	var found bool
	if err := s.db.Read(ctx, func(tx *store.Tx) error {
		var err error
		stored, found, err = loadLegacyVault(ctx, tx, userID)
		return err
	}); err != nil {
		return 0, storage(err)
	}
	if !found {
		return 0, fault.New(fault.VaultMissing, "")
	}
	env, err := parseLegacyVault(stored.Document)
	if err != nil {
		return 0, err
	}
	revision, ok := legacyRevision(stored)
	if !ok {
		return 0, fault.New(fault.VaultUnreadable, "")
	}
	passphrase, ok := asString(passV)
	if !ok {
		return 0, fault.New(fault.InvalidRequest, "")
	}
	incarnation, err := c.Accounts.Incarnation(ctx, userID)
	if err != nil {
		return 0, fault.Wrap(fault.StorageError, err, "")
	}
	select {
	case c.kdf <- struct{}{}:
	default:
		return 0, fault.New(fault.Busy, "")
	}
	records, err := openLegacyVault(env, userID, incarnation, passphrase)
	<-c.kdf
	if err != nil {
		return 0, err
	}
	all, _, err := c.resources(ctx, userID)
	if err != nil {
		return 0, err
	}
	created := 0
	err = s.mutate(ctx, userID, func(_ *store.Tx, d *credDoc) error {
		if slices.Contains(d.imports, revision) {
			return nil
		}
		for _, rec := range records {
			res, rerr := resolve(all, rec.ResourceID)
			name := rec.ResourceID
			if rerr == nil {
				name, _ = asString(res.Name)
			}
			if !validText(name, MaxNameBytes, false) {
				name = "Imported password"
			}
			data := pyjson.Object([]pyjson.Member{{Name: "name", Value: pyjson.String(name)}, {Name: "password", Value: pyjson.String(rec.Password)}})
			cred, err := s.createNamed(userID, d, data)
			if err != nil {
				return err
			}
			created++
			if _, assigned := d.assignment(rec.ResourceID); !assigned && rerr == nil {
				d.assign(Assignment{ResourceID: rec.ResourceID, CredentialID: cred.ID, Fingerprint: rec.Fingerprint, Generation: randomHex(32)})
			}
		}
		d.imports = append(d.imports, revision)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return created, nil
}

package vault

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
	"github.com/bifrost0x/webssh/internal/store"
)

func wantCode(t *testing.T, err error, code fault.Code) {
	t.Helper()
	if got := fault.CodeOf(err); got != code {
		t.Fatalf("code %q (%v), want %q", got, err, code)
	}
}

func TestUploadListSigner(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	k := goldenByLabel(t, "ecdsa-p384-pem")
	name := strings.Repeat("ä", MaxNameRunes) // 128 characters, 256 bytes
	s := r.upload(t, alice, name, k.pem(t))
	if s.KeyType != KeyECDSA || !s.Usable || s.Name != name || s.UploadedAt != "2026-11-26T10:11:12.345678+00:00" {
		t.Fatalf("summary %+v", s)
	}
	list, err := r.svc.List(as(alice))
	if err != nil || len(list) != 1 || list[0] != s {
		t.Fatalf("list %+v %v", list, err)
	}
	signer, err := r.svc.Signer(context.Background(), alice.UserID, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	want, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(k.Public))
	if !bytes.Equal(signer.PublicKey().Marshal(), want.Marshal()) {
		t.Error("signer has another public key")
	}
	// Another user sees nothing and cannot use the key.
	bob := principaltest.User(2)
	if list, err := r.svc.List(as(bob)); err != nil || len(list) != 0 {
		t.Fatalf("bob list %+v %v", list, err)
	}
	if _, err := r.svc.Signer(context.Background(), bob.UserID, s.ID); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("bob signer: %v", err)
	}
}

// The database holds the key only sealed, with its public facts.
func TestKeyIsSealedAtRest(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	plain := newEd25519PEM(t)
	s := r.upload(t, alice, "k", plain)
	var row keyRow
	if err := r.db.Read(context.Background(), func(tx *store.Tx) (err error) {
		row, _, err = getRow(context.Background(), tx, alice.UserID, s.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	body := plain[len("-----BEGIN OPENSSH PRIVATE KEY-----\n") : len("-----BEGIN OPENSSH PRIVATE KEY-----\n")+40]
	if bytes.Contains(row.Sealed, body) || bytes.Contains(row.Sealed, []byte("PRIVATE KEY")) {
		t.Fatal("private key stored in clear")
	}
	if !strings.HasPrefix(row.PublicKey, "ssh-ed25519 ") || !strings.HasPrefix(row.Fingerprint, "SHA256:") || row.State != stateUsable {
		t.Fatalf("row %+v", row)
	}
}

// A sealed key moved to another row or user does not open: the summary
// says unusable and the signer refuses.
func TestSealedKeyBoundToRow(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	a := r.upload(t, alice, "a", newEd25519PEM(t))
	b := r.upload(t, alice, "b", newEd25519PEM(t))
	ctx := context.Background()
	if err := r.db.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE vault_ssh_keys SET private_key = (SELECT private_key FROM vault_ssh_keys WHERE id = ?) WHERE id = ?`, a.ID, b.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	list, err := r.svc.List(as(alice))
	if err != nil || !list[0].Usable || list[1].Usable {
		t.Fatalf("list %+v %v", list, err)
	}
	if _, err := r.svc.Signer(ctx, alice.UserID, b.ID); fault.CodeOf(err) != fault.InvalidValue {
		t.Fatalf("signer of moved key: %v", err)
	}
}

func TestUploadValidation(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	ctx := as(alice)
	key := string(newEd25519PEM(t))
	cases := map[string]struct {
		u    Upload
		text string
	}{
		"no name":         {Upload{Content: key}, textNameContentRequired},
		"no content":      {Upload{Name: "k"}, textNameContentRequired},
		"blank name":      {Upload{Name: "  ", Content: key}, textInvalidName},
		"long name":       {Upload{Name: strings.Repeat("x", MaxNameRunes+1), Content: key}, textNameTooLong},
		"large":           {Upload{Name: "k", Content: strings.Repeat("x", MaxKeyBytes+1)}, textContentTooLarge},
		"long passphrase": {Upload{Name: "k", Content: key, Passphrase: strings.Repeat("p", MaxPassphraseBytes+1)}, textPassphraseTooLong},
		"garbage":         {Upload{Name: "k", Content: "garbage"}, textInvalidKey},
		"dsa":             {Upload{Name: "k", Content: "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----\n"}, textDSA},
		"pkcs8 encrypted": {Upload{Name: "k", Content: string(goldenByLabel(t, "ed25519-pkcs8-passphrase").pem(t)), Passphrase: goldenPassphrase}, textEncryptedPKCS8},
	}
	for name, c := range cases {
		_, err := r.svc.Upload(ctx, c.u)
		e, ok := fault.From(err)
		if !ok || e.Code != fault.InvalidValue || e.Message != c.text {
			t.Errorf("%s: %v", name, err)
		}
	}
	if n := len(r.stepUp.Calls()); n != 0 {
		t.Fatalf("invalid uploads spent %d grants", n)
	}
}

// A protected key asks for its passphrase without spending the grant; the
// retry with the passphrase and the same grant stores the key.
func TestUploadPassphraseFlow(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	ctx := as(alice)
	k := goldenByLabel(t, "ed25519-openssh-passphrase")
	grant := r.grant(alice, principal.ActionKeyUpload, userTarget(alice))
	for _, pass := range []string{"", "wrong"} {
		_, err := r.svc.Upload(ctx, Upload{Name: "k", Content: string(k.pem(t)), Passphrase: pass, Grant: grant})
		wantCode(t, err, fault.InvalidValue)
		if fault.DetailsOf(err)[DetailPassphraseRequired] != true {
			t.Fatalf("passphrase %q: details %v", pass, fault.DetailsOf(err))
		}
	}
	s, err := r.svc.Upload(ctx, Upload{Name: "k", Content: string(k.pem(t)), Passphrase: goldenPassphrase, Grant: grant})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Signer(context.Background(), alice.UserID, s.ID); err != nil {
		t.Fatalf("stored key without passphrase: %v", err)
	}
}

// Step-up negatives: no grant, a grant of another session, of another
// action, of another target, a spent grant and an expired one (the
// service says step_up_required for every failure, which is all the vault
// relies on).
func TestStepUpRequired(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	ctx := as(alice)
	key := string(newEd25519PEM(t))
	other := alice
	other.SessionID = "another-session"

	upload := func(grant string) error {
		_, err := r.svc.Upload(ctx, Upload{Name: "k", Content: key, Grant: grant})
		return err
	}
	wantCode(t, upload(""), fault.StepUpRequired)
	wantCode(t, upload(r.grant(other, principal.ActionKeyUpload, userTarget(alice))), fault.StepUpRequired)
	wantCode(t, upload(r.grant(alice, principal.ActionKeyDelete, userTarget(alice))), fault.StepUpRequired)
	wantCode(t, upload(r.grant(alice, principal.ActionKeyUpload, "2")), fault.StepUpRequired)
	grant := r.grant(alice, principal.ActionKeyUpload, userTarget(alice))
	if err := upload(grant); err != nil {
		t.Fatal(err)
	}
	wantCode(t, upload(grant), fault.StepUpRequired) // spent

	list, _ := r.svc.List(ctx)
	if len(list) != 1 {
		t.Fatalf("keys stored: %d, want 1", len(list))
	}
	id := list[0].ID
	second := r.upload(t, alice, "second", newEd25519PEM(t))

	replace := func(grant string) error {
		_, err := r.svc.Replace(ctx, Replace{ID: id, Content: string(newEd25519PEM(t)), Grant: grant})
		return err
	}
	wantCode(t, replace(""), fault.StepUpRequired)
	wantCode(t, replace(r.grant(alice, principal.ActionKeyReplace, second.ID)), fault.StepUpRequired)
	wantCode(t, replace(r.grant(alice, principal.ActionKeyUpload, id)), fault.StepUpRequired)
	wantCode(t, replace(r.grant(other, principal.ActionKeyReplace, id)), fault.StepUpRequired)

	wantCode(t, r.svc.Delete(ctx, id, ""), fault.StepUpRequired)
	wantCode(t, r.svc.Delete(ctx, id, r.grant(alice, principal.ActionKeyDelete, second.ID)), fault.StepUpRequired)
	wantCode(t, r.svc.Delete(ctx, id, r.grant(alice, principal.ActionKeyReplace, id)), fault.StepUpRequired)
	wantCode(t, r.svc.Delete(ctx, id, r.grant(other, principal.ActionKeyDelete, id)), fault.StepUpRequired)

	expired := &expiredStepUp{}
	r.svc.stepUp = expired
	wantCode(t, upload("issued-long-ago"), fault.StepUpRequired)
	if expired.calls != 1 {
		t.Fatal("expired grant not checked")
	}
	if list, _ := r.svc.List(ctx); len(list) != 2 {
		t.Fatalf("refused operations changed the keys: %d", len(list))
	}
}

// expiredStepUp answers like the real service for a grant past
// STEP_UP_MAX_AGE_SECONDS.
type expiredStepUp struct{ calls int }

func (e *expiredStepUp) Consume(context.Context, principal.Principal, principal.Action, string, string) error {
	e.calls++
	return fault.New(fault.StepUpRequired, "")
}

func TestReplace(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	ctx := as(alice)
	s := r.upload(t, alice, "deploy", newEd25519PEM(t))
	next := newEd25519PEM(t)

	_, err := r.svc.Replace(ctx, Replace{ID: s.ID, Content: string(goldenByLabel(t, "rsa2048-pem").pem(t)), Grant: r.grant(alice, principal.ActionKeyReplace, s.ID)})
	if e, _ := fault.From(err); e == nil || e.Message != "Replacement key must use the same key type (Ed25519)" {
		t.Fatalf("type change: %v", err)
	}
	_, err = r.svc.Replace(ctx, Replace{ID: "missing", Content: string(next), Grant: r.grant(alice, principal.ActionKeyReplace, "missing")})
	wantCode(t, err, fault.NotFound)
	_, err = r.svc.Replace(ctx, Replace{ID: s.ID})
	wantCode(t, err, fault.InvalidValue)

	got, err := r.svc.Replace(ctx, Replace{ID: s.ID, Content: string(next), Grant: r.grant(alice, principal.ActionKeyReplace, s.ID)})
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != s.ID || got.Name != s.Name || got.UploadedAt != s.UploadedAt || !got.Usable {
		t.Fatalf("replaced %+v, was %+v", got, s)
	}
	parsed, _ := parseKey(next, nil)
	signer, err := r.svc.Signer(context.Background(), alice.UserID, s.ID)
	if err != nil || !bytes.Equal(signer.PublicKey().Marshal(), parsed.signer.PublicKey().Marshal()) {
		t.Fatalf("signer after replace: %v", err)
	}
	// Bob cannot replace Alice's key, even with a grant for its ID.
	bob := principaltest.User(2)
	_, err = r.svc.Replace(as(bob), Replace{ID: s.ID, Content: string(newEd25519PEM(t)), Grant: r.grant(bob, principal.ActionKeyReplace, s.ID)})
	wantCode(t, err, fault.NotFound)
}

func TestRename(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	ctx := as(alice)
	s := r.upload(t, alice, "old", newEd25519PEM(t))
	got, err := r.svc.Rename(ctx, s.ID, "  new name  ")
	if err != nil || got.Name != "new name" || !got.Usable || got.ID != s.ID {
		t.Fatalf("rename %+v %v", got, err)
	}
	for name, c := range map[string]struct {
		id, name string
		code     fault.Code
	}{
		"blank":   {s.ID, " ", fault.InvalidValue},
		"long":    {s.ID, strings.Repeat("ß", MaxNameRunes+1), fault.InvalidValue},
		"no id":   {"", "x", fault.NotFound},
		"missing": {"missing", "x", fault.NotFound},
	} {
		if _, err := r.svc.Rename(ctx, c.id, c.name); fault.CodeOf(err) != c.code {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := r.svc.Rename(as(principaltest.User(2)), s.ID, "stolen"); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("other user: %v", err)
	}
	if len(r.stepUp.Calls()) != 1 { // only the upload
		t.Fatal("rename must not need a step-up")
	}
}

func TestDelete(t *testing.T) {
	r := newRig(t, Limits{})
	alice := principaltest.User(1)
	ctx := as(alice)
	s := r.upload(t, alice, "k", newEd25519PEM(t))
	wantCode(t, r.svc.Delete(ctx, "", "x"), fault.InvalidValue)
	wantCode(t, r.svc.Delete(ctx, "missing", r.grant(alice, principal.ActionKeyDelete, "missing")), fault.NotFound)
	bob := principaltest.User(2)
	wantCode(t, r.svc.Delete(as(bob), s.ID, r.grant(bob, principal.ActionKeyDelete, s.ID)), fault.NotFound)
	if err := r.svc.Delete(ctx, s.ID, r.grant(alice, principal.ActionKeyDelete, s.ID)); err != nil {
		t.Fatal(err)
	}
	if list, _ := r.svc.List(ctx); len(list) != 0 {
		t.Fatal("key still listed")
	}
	if _, err := r.svc.Signer(context.Background(), alice.UserID, s.ID); fault.CodeOf(err) != fault.NotFound {
		t.Fatalf("signer after delete: %v", err)
	}
}

func TestLimits(t *testing.T) {
	small := goldenByLabel(t, "ed25519-openssh").pem(t)
	big := goldenByLabel(t, "rsa2048-pem").pem(t)

	r := newRig(t, Limits{MaxRecords: 2, MaxStoreBytes: 1 << 20})
	alice := principaltest.User(1)
	r.upload(t, alice, "a", small)
	r.upload(t, alice, "b", small)
	_, err := r.svc.Upload(as(alice), Upload{Name: "c", Content: string(small), Grant: r.grant(alice, principal.ActionKeyUpload, userTarget(alice))})
	if e, _ := fault.From(err); e == nil || e.Code != fault.Conflict || e.Message != textStorageLimit {
		t.Fatalf("record limit: %v", err)
	}
	if calls := r.stepUp.Calls(); calls[len(calls)-1].Err != nil || len(calls) != 2 {
		t.Fatal("a refused upload must not spend its grant")
	}
	// The limit is per user.
	r.upload(t, principaltest.User(2), "a", small)

	// Byte limit: growth is refused, shrinking a store above the limit is
	// allowed.
	r = newRig(t, Limits{MaxRecords: 10, MaxStoreBytes: 3000})
	ed := r.upload(t, alice, "ed", small)
	rsaKey := r.upload(t, alice, "rsa", big)
	_ = ed
	r.svc.limits.MaxStoreBytes = 1000 // now above the limit
	_, err = r.svc.Upload(as(alice), Upload{Name: "more", Content: string(small), Grant: r.grant(alice, principal.ActionKeyUpload, userTarget(alice))})
	wantCode(t, err, fault.Conflict)
	if _, err := r.svc.Rename(as(alice), rsaKey.ID, "renamed"); err != nil {
		t.Fatalf("rename above limit: %v", err)
	}
	other := goldenByLabel(t, "rsa2048-openssh").pem(t) // larger than the PEM form
	parsedOld, _ := parseKey(big, nil)
	parsedNew, _ := parseKey(other, nil)
	if len(parsedNew.stored) > len(parsedOld.stored) {
		_, err = r.svc.Replace(as(alice), Replace{ID: rsaKey.ID, Content: string(other), Grant: r.grant(alice, principal.ActionKeyReplace, rsaKey.ID)})
		wantCode(t, err, fault.Conflict)
		if _, err := r.svc.Replace(as(alice), Replace{ID: rsaKey.ID, Content: string(big), Grant: r.grant(alice, principal.ActionKeyReplace, rsaKey.ID)}); err != nil {
			t.Fatalf("same size above limit: %v", err)
		}
	} else {
		t.Fatalf("fixture sizes changed: %d %d", len(parsedNew.stored), len(parsedOld.stored))
	}
}

func TestPrincipalRequired(t *testing.T) {
	r := newRig(t, Limits{})
	recovery := principaltest.User(1)
	recovery.Recovery = true
	for name, ctx := range map[string]context.Context{"none": context.Background(), "recovery": as(recovery)} {
		if _, err := r.svc.List(ctx); err == nil {
			t.Errorf("%s: list allowed", name)
		}
		if _, err := r.svc.Upload(ctx, Upload{Name: "k", Content: "x"}); err == nil {
			t.Errorf("%s: upload allowed", name)
		}
		if _, err := r.svc.Rename(ctx, "id", "x"); err == nil {
			t.Errorf("%s: rename allowed", name)
		}
		if _, err := r.svc.Replace(ctx, Replace{ID: "id", Content: "x"}); err == nil {
			t.Errorf("%s: replace allowed", name)
		}
		if err := r.svc.Delete(ctx, "id", "g"); err == nil {
			t.Errorf("%s: delete allowed", name)
		}
	}
}

// No error of any path carries key material or the passphrase; the
// transports log Error().
func TestErrorsCarryNoSecrets(t *testing.T) {
	r := newRig(t, Limits{MaxRecords: 1, MaxStoreBytes: 1 << 20})
	alice := principaltest.User(1)
	ctx := as(alice)
	protected := goldenByLabel(t, "rsa2048-pem-passphrase").pem(t)
	plain := goldenByLabel(t, "rsa2048-pem").pem(t)
	secretLine := strings.Split(string(plain), "\n")[2]
	protectedLine := strings.Split(string(protected), "\n")[4]
	const passphrase = "my-secret-passphrase-123"
	var errs []error
	_, err := r.svc.Upload(ctx, Upload{Name: "k", Content: string(protected), Passphrase: passphrase})
	errs = append(errs, err)
	_, err = r.svc.Upload(ctx, Upload{Name: "k", Content: string(protected)})
	errs = append(errs, err)
	_, err = r.svc.Upload(ctx, Upload{Name: "k", Content: string(plain[:len(plain)/2])})
	errs = append(errs, err)
	_, err = r.svc.Upload(ctx, Upload{Name: "k", Content: string(plain)}) // no grant
	errs = append(errs, err)
	r.upload(t, alice, "first", newEd25519PEM(t))
	_, err = r.svc.Upload(ctx, Upload{Name: "k", Content: string(plain), Grant: r.grant(alice, principal.ActionKeyUpload, userTarget(alice))})
	errs = append(errs, err)
	for i, err := range errs {
		if err == nil {
			t.Fatalf("case %d succeeded", i)
		}
		text := err.Error()
		for _, secret := range []string{secretLine, protectedLine, passphrase, "PRIVATE KEY"} {
			if strings.Contains(text, secret) {
				t.Errorf("case %d: error text carries %q", i, secret[:min(len(secret), 12)])
			}
		}
	}
}

func TestNewRequiresOptions(t *testing.T) {
	r := newRig(t, Limits{})
	for name, o := range map[string]Options{
		"db":      {Sealer: r.ring, StepUp: r.stepUp, Limits: Limits{1, 1}},
		"sealer":  {DB: r.db, StepUp: r.stepUp, Limits: Limits{1, 1}},
		"step-up": {DB: r.db, Sealer: r.ring, Limits: Limits{1, 1}},
		"limits":  {DB: r.db, Sealer: r.ring, StepUp: r.stepUp},
	} {
		if _, err := New(o); err == nil {
			t.Errorf("%s missing: accepted", name)
		}
	}
}

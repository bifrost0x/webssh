package webauthn

import (
	"bytes"
	json "encoding/json/v2"
	"strconv"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

func TestDeletePasskey(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p, other := user(7), user(8)
	_, id := e.enrol(t, p, AlgES256, "")
	_, otherID := e.enrol(t, other, AlgES256, "")
	path := "/api/webauthn/credentials/" + strconv.FormatInt(id, 10)
	for _, c := range []call{
		{method: "DELETE", path: "/api/webauthn/credentials/" + strconv.FormatInt(otherID, 10), p: &p, grant: "ok"},
		{method: "DELETE", path: "/api/webauthn/credentials/999", p: &p, grant: "ok"},
		{method: "DELETE", path: "/api/webauthn/credentials/01", p: &p, grant: "ok"},
		{method: "DELETE", path: "/api/webauthn/credentials/-1", p: &p, grant: "ok"},
	} {
		if status, out := e.do(t, c); status != 404 || str(t, out["error"]) != "Passkey not found" {
			t.Fatalf("%s: %d %v", c.path, status, out)
		}
	}
	if status, out := e.do(t, call{method: "DELETE", path: path, p: &p}); status != 403 || code(t, out) != "step_up_required" {
		t.Fatalf("no grant: %d %v", status, out)
	}
	// With MFA on and no other factor the last passkey stays.
	e.accounts.mfa[7] = true
	if status, out := e.do(t, call{method: "DELETE", path: path, p: &p, grant: "ok"}); status != 409 || code(t, out) != "last_factor_required" {
		t.Fatalf("last factor: %d %v", status, out)
	}
	// A TOTP authenticator is a remaining factor.
	e.svc.MFA.TOTP = fakeTOTP{n: 1}
	if status, out := e.do(t, call{method: "DELETE", path: path, p: &p, grant: "ok"}); status != 200 || string(out["ok"]) != "true" {
		t.Fatalf("delete: %d %v", status, out)
	}
	if got := e.stepUp.consumed; got[len(got)-1] != "passkey.delete:"+strconv.FormatInt(id, 10) {
		t.Fatalf("grants %v", got)
	}
	if ok, _ := e.svc.Owned(t.Context(), 7, id); ok {
		t.Fatal("passkey still there")
	}
	if ok, _ := e.svc.Owned(t.Context(), 8, otherID); !ok {
		t.Fatal("other account's passkey removed")
	}
	if err := e.svc.OwnsTarget(t.Context(), other, strconv.FormatInt(otherID, 10)); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{strconv.FormatInt(id, 10), "x", "", "+1"} {
		if err := e.svc.OwnsTarget(t.Context(), other, target); !fault.Is(err, fault.NotFound) {
			t.Fatalf("target %q: %v", target, err)
		}
	}
}

func TestEnableMFA(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := user(7)
	enable := func(body map[string]any, grant string) (int, string, []string) {
		status, out := e.do(t, call{method: "POST", path: "/api/webauthn/mfa", p: &p, body: body, grant: grant})
		var codes []string
		_ = json.Unmarshal(out["recovery_codes"], &codes)
		msg := ""
		if out["error"] != nil {
			msg = str(t, out["error"])
		}
		return status, msg, codes
	}
	confirm := map[string]any{"confirm_enable_mfa": true}
	if s, msg, _ := enable(map[string]any{"confirm_enable_mfa": "yes"}, "ok"); s != 400 || msg != "MFA activation must be confirmed" {
		t.Fatalf("unconfirmed: %d %s", s, msg)
	}
	if s, _, _ := enable(confirm, ""); s != 403 {
		t.Fatalf("no grant: %d", s)
	}
	if s, msg, _ := enable(confirm, "ok"); s != 409 || msg != "Add a Passkey before enabling MFA" {
		t.Fatalf("no passkey: %d %s", s, msg)
	}
	e.enrol(t, p, AlgES256, "")
	e.gates.set(auth.FeatureRecovery, false)
	if s, msg, _ := enable(confirm, "ok"); s != 409 || msg != "Recovery codes must be active before enabling MFA" {
		t.Fatalf("recovery off: %d %s", s, msg)
	}
	e.gates.set(auth.FeatureRecovery, true)
	s, _, codes := enable(confirm, "ok")
	if s != 200 || len(codes) != auth.RecoveryCodeCount || !e.accounts.mfa[7] {
		t.Fatalf("enable: %d %v", s, codes)
	}
	if ok, err := e.svc.Recovery.Consume(t.Context(), 7, codes[0]); err != nil || !ok {
		t.Fatalf("recovery code does not work: %v", err)
	}
	if s, msg, _ := enable(confirm, "ok"); s != 409 || msg != "MFA is already enabled" {
		t.Fatalf("again: %d %s", s, msg)
	}
	if !e.audit.has("MFA_ENABLED") {
		t.Fatal("not audited")
	}
	state, err := e.svc.MFA.State(t.Context(), 7)
	if err != nil || !state.MFAEnabled || state.Passkeys != 1 {
		t.Fatalf("security state %+v %v", state, err)
	}
}

func TestStepUpAssertion(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, _ := e.enrol(t, user(7), AlgRS256, "")
	b, _ := e.enrol(t, user(8), AlgES256, "")
	ctx := t.Context()
	binding := "step-up:session-of-user-7:1"
	opts, err := e.svc.AssertionOptions(ctx, 7, binding)
	if err != nil {
		t.Fatal(err)
	}
	var o requestOptions
	if err := json.Unmarshal(opts, &o); err != nil || len(o.AllowCredentials) != 1 || o.AllowCredentials[0].ID != encodeB64URL(a.id) || o.UserVerification != "required" {
		t.Fatalf("options %s", opts)
	}
	ch, _ := decodeB64URL(o.Challenge)
	// Another intent's binding, another account and a sign-in challenge do
	// not answer it; each attempt uses the challenge up.
	if err := e.svc.VerifyAssertion(ctx, 7, binding+"0", a.assert(t, ch, assertOpts{})); err == nil {
		t.Fatal("other binding")
	}
	opts, _ = e.svc.AssertionOptions(ctx, 7, binding)
	_ = json.Unmarshal(opts, &o)
	ch, _ = decodeB64URL(o.Challenge)
	if err := e.svc.VerifyAssertion(ctx, 7, binding, b.assert(t, ch, assertOpts{})); !fault.Is(err, fault.AuthenticationNeeded) {
		t.Fatalf("other account's passkey: %v", err)
	}
	if err := e.svc.VerifyAssertion(ctx, 7, binding, a.assert(t, ch, assertOpts{})); err == nil {
		t.Fatal("challenge reused after a failure")
	}
	opts, _ = e.svc.AssertionOptions(ctx, 7, binding)
	_ = json.Unmarshal(opts, &o)
	ch, _ = decodeB64URL(o.Challenge)
	if _, err := e.svc.SignIn(ctx, binding, 0, a.assert(t, ch, assertOpts{})); err == nil {
		t.Fatal("step-up challenge answered a sign-in")
	}
	opts, _ = e.svc.AssertionOptions(ctx, 7, binding)
	_ = json.Unmarshal(opts, &o)
	ch, _ = decodeB64URL(o.Challenge)
	if err := e.svc.VerifyAssertion(ctx, 7, binding, a.assert(t, ch, assertOpts{})); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.AssertionOptions(ctx, 9, binding); !fault.Is(err, fault.Conflict) {
		t.Fatalf("account without passkeys: %v", err)
	}
	if ok, _ := (Factor{e.svc}).Enrolled(ctx, 7); !ok || (Factor{}).Kind() != "passkey" {
		t.Fatal("factor")
	}
	if err := (Factor{e.svc}).Verify(ctx, 7, nil); err == nil {
		t.Fatal("generic factor verification accepted")
	}
}

func TestChallengeBounds(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c := e.svc.challenges()
	ctx := t.Context()
	// One registration per ceremony, at most five open per account.
	for i := range maxRegistrations + 3 {
		if _, err := c.issue(ctx, purposeRegister, 7, "register-binding-"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	count := func(where string, args ...any) int {
		var n int
		_ = e.svc.DB.Read(ctx, func(tx *store.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_challenges WHERE `+where, args...).Scan(&n)
		})
		return n
	}
	if n := count(`user_id = 7`); n != maxRegistrations {
		t.Fatalf("%d open registrations", n)
	}
	if _, err := c.consume(ctx, purposeRegister, 7, "register-binding-0"); err == nil {
		t.Fatal("evicted registration still answers")
	}
	if _, err := c.consume(ctx, purposeRegister, 7, "register-binding-"+strconv.Itoa(maxRegistrations+2)); err != nil {
		t.Fatal(err)
	}
	// A new challenge of the same purpose and binding replaces the old.
	first, _ := c.issue(ctx, purposeLogin, 0, "login-binding-0001")
	second, _ := c.issue(ctx, purposeLogin, 0, "login-binding-0001")
	if bytes.Equal(first, second) || len(second) != challengeBytes {
		t.Fatal("challenge not fresh")
	}
	got, err := c.consume(ctx, purposeLogin, 0, "login-binding-0001")
	if err != nil || !bytes.Equal(got, second) {
		t.Fatalf("consume: %v", err)
	}
	// A challenge for an account does not answer for none or another.
	_, _ = c.issue(ctx, purposeMFA, 7, "mfa-binding-00001")
	if _, err := c.consume(ctx, purposeMFA, 0, "mfa-binding-00001"); err == nil {
		t.Fatal("account challenge consumed without account")
	}
	if _, err := c.consume(ctx, purposeMFA, 8, "mfa-binding-00001"); err == nil {
		t.Fatal("account challenge consumed by another account")
	}
	// Expired challenges are purged by the next issue.
	_, _ = c.issue(ctx, purposeLogin, 0, "login-binding-0002")
	e.clock.Advance(ChallengeTTL + time.Second)
	_, _ = c.issue(ctx, purposeLogin, 0, "login-binding-0003")
	if n := count(`binding_hash = ?`, bindingHash("login-binding-0002")); n != 0 {
		t.Fatal("expired challenge kept")
	}
	// A sealed challenge moved to another purpose or binding does not open.
	_ = e.svc.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE webauthn_challenges SET binding_hash = ? WHERE binding_hash = ?`,
			bindingHash("login-binding-0004"), bindingHash("login-binding-0003"))
		return err
	})
	if _, err := c.consume(ctx, purposeLogin, 0, "login-binding-0004"); err == nil {
		t.Fatal("moved challenge opened")
	}
	if _, err := c.issue(ctx, purposeLogin, 0, "short"); !fault.Is(err, fault.InvalidRequest) {
		t.Fatalf("short binding: %v", err)
	}
}

func TestChallengeTableIsBounded(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	c := e.svc.challenges()
	ctx := t.Context()
	// Fill the table to its bound in one statement, then add more.
	now := e.clock.Now()
	err := e.svc.DB.Write(ctx, func(tx *store.Tx) error {
		_, err := tx.ExecContext(ctx, `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
			INSERT INTO webauthn_challenges (purpose, binding_hash, user_id, sealed_challenge, created_at, expires_at)
			SELECT 'login', randomblob(32), NULL, x'00', ?, ? FROM n`, maxChallenges, now.UnixMicro(), now.Add(ChallengeTTL).UnixMicro())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 5 {
		if _, err := c.issue(ctx, purposeLogin, 0, "flood-binding-00-"+strconv.Itoa(i)); err != nil {
			t.Fatal(err)
		}
	}
	var n int
	_ = e.svc.DB.Read(ctx, func(tx *store.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT count(*) FROM webauthn_challenges`).Scan(&n)
	})
	if n != maxChallenges {
		t.Fatalf("%d challenges", n)
	}
	for i := range 5 {
		if _, err := c.consume(ctx, purposeLogin, 0, "flood-binding-00-"+strconv.Itoa(i)); err != nil {
			t.Fatalf("newest challenge %d evicted: %v", i, err)
		}
	}
}

// TestMigratedPasskeys imports the golden passkeys as the migration does
// (E10) and signs in with their recorded assertions under the configured
// RP ID and origin; the stored counter then advances and a replay fails.
func TestMigratedPasskeys(t *testing.T) {
	t.Parallel()
	g := loadGolden(t)
	e := newEnv(t)
	e.svc.RP = g.RP
	ctx := t.Context()
	for _, v := range g.Vectors {
		reg, err := g.RP.VerifyRegistration(v.Registration, registrationChallenge(t, v.Registration))
		if err != nil {
			t.Fatal(err)
		}
		err = e.svc.DB.Write(ctx, func(tx *store.Tx) error {
			return e.svc.ImportTx(ctx, tx, Imported{ID: v.RowID, UserID: g.UserID, CredentialID: reg.CredentialID, COSEKey: reg.COSEKey,
				SignCount: int64(v.StoredCount), Transports: reg.Transports, Name: v.Name, CreatedAt: time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := e.svc.List(ctx, g.UserID)
	if err != nil || len(list) != len(g.Vectors) || list[2].Name != g.Vectors[2].Name {
		t.Fatalf("imported %+v %v", list, err)
	}
	for _, v := range g.Vectors {
		challenge, _ := decodeB64URL(v.Challenge)
		binding := "golden-browser-" + strconv.FormatInt(v.RowID, 10)
		plant(t, e, purposeLogin, 0, binding, challenge)
		userID, err := e.svc.SignIn(ctx, binding, 0, v.Assertion)
		if err != nil || userID != g.UserID {
			t.Fatalf("%s: %d %v", v.Name, userID, err)
		}
		var count int64
		var be, bs bool
		_ = e.svc.DB.Read(ctx, func(tx *store.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT sign_count, backup_eligible, backup_state FROM webauthn_credentials WHERE id = ?`, v.RowID).Scan(&count, &be, &bs)
		})
		if count != int64(v.AssertionCount) || be != v.Flags["BE"] || bs != v.Flags["BS"] {
			t.Fatalf("%s: stored counter %d BE %v BS %v", v.Name, count, be, bs)
		}
		plant(t, e, purposeLogin, 0, binding, challenge)
		_, err = e.svc.SignIn(ctx, binding, 0, v.Assertion)
		if v.AssertionCount > 0 && err == nil {
			t.Fatalf("%s: replayed assertion accepted", v.Name)
		}
		if v.AssertionCount == 0 && err != nil {
			// A synced passkey keeps counter 0; the challenge, not the
			// counter, stops replays (see TestUsernamelessSignIn).
			t.Fatalf("%s: counter-0 passkey: %v", v.Name, err)
		}
	}
	// A key that does not parse stops the import.
	err = e.svc.DB.Write(ctx, func(tx *store.Tx) error {
		return e.svc.ImportTx(ctx, tx, Imported{ID: 99, UserID: g.UserID, CredentialID: []byte{1}, COSEKey: []byte{0xa0}, Name: "x"})
	})
	if err == nil {
		t.Fatal("unparseable key imported")
	}
}

// plant stores a known challenge, as recorded in the golden data set.
func plant(t *testing.T, e *env, purpose string, userID int64, binding string, challenge []byte) {
	t.Helper()
	hash := bindingHash(binding)
	sealed, err := e.svc.Ring.Seal(keyring.WebAuthnChallenge, challengeAAD(purpose, hash), challenge)
	if err != nil {
		t.Fatal(err)
	}
	now := e.clock.Now()
	err = e.svc.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `INSERT INTO webauthn_challenges (purpose, binding_hash, user_id, sealed_challenge, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?, ?)`, purpose, hash, nullableUser(userID), sealed, now.UnixMicro(), now.Add(ChallengeTTL).UnixMicro())
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

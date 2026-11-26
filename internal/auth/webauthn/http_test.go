package webauthn

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/principal"
)

func code(t *testing.T, out map[string]jsontext.Value) string {
	t.Helper()
	return str(t, out["code"])
}

func TestRoutesAreGated(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.gates.set(auth.FeaturePasskey, false)
	p := user(7)
	for _, c := range []call{
		{method: "GET", path: "/api/webauthn/credentials", p: &p},
		{method: "DELETE", path: "/api/webauthn/credentials/1", p: &p},
		{method: "POST", path: "/api/webauthn/mfa", p: &p},
		{method: "POST", path: "/api/webauthn/register/options", p: &p, grant: "ok"},
		{method: "POST", path: "/api/webauthn/register/verify", p: &p},
		{method: "POST", path: "/api/webauthn/auth/options", browser: browserID(1)},
		{method: "POST", path: "/api/webauthn/auth/verify", browser: browserID(1)},
	} {
		if status, out := e.do(t, c); status != 404 || code(t, out) != "not_found" {
			t.Errorf("%s %s: %d %v", c.method, c.path, status, out)
		}
	}
	if len(e.stepUp.consumed) != 0 {
		t.Fatal("a gated route consumed a grant")
	}
}

func TestRegistration(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := user(7)
	// Without a grant nothing starts.
	if status, out := e.do(t, call{method: "POST", path: "/api/webauthn/register/options", body: map[string]any{}, p: &p}); status != 403 || code(t, out) != "step_up_required" {
		t.Fatalf("no grant: %d %v", status, out)
	}
	a, id := e.enrol(t, p, AlgES256, "  Laptop  ")
	if got := e.stepUp.consumed; len(got) != 1 || got[0] != "passkey.enroll:7" {
		t.Fatalf("grants %v", got)
	}
	status, out := e.do(t, call{method: "GET", path: "/api/webauthn/credentials", p: &p})
	var list []credentialJSONOut
	if err := json.Unmarshal(out["credentials"], &list); status != 200 || err != nil || len(list) != 1 ||
		list[0].ID != id || list[0].Name != "Laptop" || list[0].LastUsedAt != nil || list[0].CreatedAt != "2026-11-26T12:00:00" {
		t.Fatalf("list %d %s", status, out["credentials"])
	}
	if !e.audit.has("WEBAUTHN_CREDENTIAL_REGISTERED") {
		t.Fatal("no audit event")
	}
	// The next registration excludes the first credential; a legacy
	// upgrade excludes nothing.
	_, opts := e.do(t, call{method: "POST", path: "/api/webauthn/register/options", body: map[string]any{}, p: &p, grant: "ok"})
	if !strings.Contains(string(opts["excludeCredentials"]), encodeB64URL(a.id)) || str(t, opts["ceremony"]) == "" {
		t.Fatalf("exclude list %s", opts["excludeCredentials"])
	}
	var userEntity struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(opts["user"], &userEntity)
	if userEntity.ID != encodeB64URL([]byte("7")) {
		t.Fatalf("user handle %q", userEntity.ID)
	}
	_, opts = e.do(t, call{method: "POST", path: "/api/webauthn/register/options", body: map[string]any{"legacy_upgrade": true}, p: &p, grant: "ok"})
	if string(opts["excludeCredentials"]) != "[]" {
		t.Fatalf("legacy upgrade excludes %s", opts["excludeCredentials"])
	}
	ch, _ := decodeB64URL(str(t, opts["challenge"]))
	ceremony := str(t, opts["ceremony"])
	// The same credential again is a conflict.
	dup := a.register(t, ch, attNone)
	if status, out := e.do(t, call{method: "POST", path: "/api/webauthn/register/verify", p: &p, body: map[string]any{"ceremony": ceremony, "credential": dup}}); status != 409 || str(t, out["error"]) != "Passkey is already registered" {
		t.Fatalf("duplicate: %d %v", status, out)
	}
	// The ceremony was used up by that attempt.
	b := newAuthenticator(t, testRP, AlgEdDSA, "7")
	if status, out := e.do(t, call{method: "POST", path: "/api/webauthn/register/verify", p: &p, body: map[string]any{"ceremony": ceremony, "credential": b.register(t, ch, attNone)}}); status != 400 || str(t, out["error"]) != "Passkey registration failed" {
		t.Fatalf("reused ceremony: %d %v", status, out)
	}
	if !e.audit.has("WEBAUTHN_REGISTRATION_REJECTED") {
		t.Fatal("rejection not audited")
	}
}

func TestRegistrationRefusalsHTTP(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p, other := user(7), user(8)
	start := func() ([]byte, string) {
		_, opts := e.do(t, call{method: "POST", path: "/api/webauthn/register/options", body: map[string]any{}, p: &p, grant: "ok"})
		ch, _ := decodeB64URL(str(t, opts["challenge"]))
		return ch, str(t, opts["ceremony"])
	}
	verify := func(who principal.Principal, ceremony string, cred jsontext.Value) int {
		status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/register/verify", p: &who, body: map[string]any{"ceremony": ceremony, "credential": cred}})
		return status
	}
	ch, ceremony := start()
	a := newAuthenticator(t, testRP, AlgES256, "7")
	if s := verify(other, ceremony, a.register(t, ch, attNone)); s != 400 {
		t.Fatalf("other account used the ceremony: %d", s)
	}
	ch, ceremony = start()
	sameUserOtherSession := p
	sameUserOtherSession.SessionID = "another-session-of-user-7"
	if s := verify(sameUserOtherSession, ceremony, a.register(t, ch, attNone)); s != 400 {
		t.Fatalf("other session used the ceremony: %d", s)
	}
	ch, ceremony = start()
	e.clock.Advance(ChallengeTTL)
	if s := verify(p, ceremony, a.register(t, ch, attNone)); s != 400 {
		t.Fatalf("expired ceremony: %d", s)
	}
	for _, bad := range []string{"", "short", strings.Repeat("c", 257)} {
		if s := verify(p, bad, a.register(t, ch, attNone)); s != 400 {
			t.Fatalf("ceremony %q: %d", bad, s)
		}
	}
	_, ceremony = start()
	if s := verify(p, ceremony, jsontext.Value(`"not an object"`)); s != 400 {
		t.Fatalf("malformed credential: %d", s)
	}
	if n, _ := e.svc.Enrolled(t.Context(), 7); n {
		t.Fatal("a refused registration stored a passkey")
	}
}

func TestPasskeyLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := user(7)
	for i := range MaxPasskeys {
		e.enrol(t, p, AlgES256, "key "+strconv.Itoa(i))
	}
	if status, out := e.do(t, call{method: "POST", path: "/api/webauthn/register/options", body: map[string]any{}, p: &p, grant: "ok"}); status != 409 || str(t, out["error"]) != "Passkey limit reached" {
		t.Fatalf("eleventh: %d %v", status, out)
	}
}

func TestRecoverySessionRepairs(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := user(7)
	p.Recovery = true
	// No grant needed; the registration ends the recovery restriction.
	e.enrol(t, p, AlgES256, "")
	if len(e.stepUp.consumed) != 0 {
		t.Fatalf("grant consumed in recovery: %v", e.stepUp.consumed)
	}
	if got := e.sessions.ended; len(got) != 1 || got[0] != p.SessionID+"|passkey|false" {
		t.Fatalf("recovery ends %v", got)
	}
	if status, _ := e.do(t, call{method: "GET", path: "/api/webauthn/credentials", p: &p}); status != 200 {
		t.Fatal("recovery session cannot list passkeys")
	}
	for _, c := range []call{
		{method: "DELETE", path: "/api/webauthn/credentials/1", p: &p, grant: "ok"},
		{method: "POST", path: "/api/webauthn/mfa", p: &p, grant: "ok", body: map[string]any{"confirm_enable_mfa": true}},
	} {
		if status, _ := e.do(t, c); status != 403 {
			t.Errorf("%s in recovery: %d", c.path, status)
		}
	}
	if status, _ := e.do(t, call{method: "GET", path: "/api/webauthn/credentials"}); status != 401 {
		t.Fatalf("anonymous list: %d", status)
	}
}

func TestUsernamelessSignIn(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, id := e.enrol(t, user(7), AlgEdDSA, "phone")
	br := browserID(1)
	ch, allow := e.signInOptions(t, br)
	if len(allow) != 0 {
		t.Fatalf("allowCredentials %v", allow)
	}
	cred := a.assert(t, ch, assertOpts{})
	verify := func(browser string, cred jsontext.Value) (int, map[string]jsontext.Value) {
		return e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", browser: browser, body: map[string]any{"credential": cred}})
	}
	if status, out := verify(br, cred); status != 200 || string(out["ok"]) != "true" || out["continuation"] != nil {
		t.Fatalf("sign-in: %d %v", status, out)
	}
	if got := e.direct.signins; len(got) != 1 || got[0] != "7|passkey|PHISHING_RESISTANT" {
		t.Fatalf("sessions %v", got)
	}
	list, _ := e.svc.List(t.Context(), 7)
	if len(list) != 1 || list[0].ID != id || list[0].LastUsedAt.IsZero() {
		t.Fatalf("use not recorded: %+v", list)
	}
	// Replay of the same answer: the challenge is gone.
	if status, out := verify(br, cred); status != 401 || str(t, out["error"]) != "Passkey authentication failed" {
		t.Fatalf("replay: %d %v", status, out)
	}
	// The old answer to a new challenge does not match it.
	e.signInOptions(t, br)
	if status, _ := verify(br, cred); status != 401 {
		t.Fatalf("old answer to new challenge: %d", status)
	}
	// Another browser cannot answer this browser's challenge.
	ch, _ = e.signInOptions(t, br)
	if status, _ := verify(browserID(2), a.assert(t, ch, assertOpts{})); status != 401 {
		t.Fatalf("foreign browser: %d", status)
	}
	// Without a binding there is no ceremony.
	if status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/options", body: map[string]any{}}); status == 200 {
		t.Fatal("options without browser binding")
	}
	// A discoverable sign-in needs the user handle.
	ch, _ = e.signInOptions(t, br)
	none := ""
	if status, _ := verify(br, a.assert(t, ch, assertOpts{handle: &none})); status != 401 {
		t.Fatalf("missing handle: %d", status)
	}
	// Expired challenge.
	ch, _ = e.signInOptions(t, br)
	e.clock.Advance(ChallengeTTL)
	if status, _ := verify(br, a.assert(t, ch, assertOpts{})); status != 401 {
		t.Fatalf("expired: %d", status)
	}
	// An ineligible account gets no session.
	e.direct.refuse[7] = true
	ch, _ = e.signInOptions(t, br)
	if status, _ := verify(br, a.assert(t, ch, assertOpts{})); status != 401 || len(e.direct.signins) != 1 {
		t.Fatalf("ineligible: %d", status)
	}
	if !e.audit.has("WEBAUTHN_AUTHENTICATION_REJECTED") {
		t.Fatal("rejection not audited")
	}
	// Unknown credential.
	ch, _ = e.signInOptions(t, br)
	stranger := newAuthenticator(t, testRP, AlgES256, "7")
	if status, _ := verify(br, stranger.assert(t, ch, assertOpts{})); status != 401 {
		t.Fatalf("unknown credential: %d", status)
	}
}

func TestCounterRule(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	p := user(7)
	_, opts := e.do(t, call{method: "POST", path: "/api/webauthn/register/options", body: map[string]any{}, p: &p, grant: "ok"})
	ch, _ := decodeB64URL(str(t, opts["challenge"]))
	a := newAuthenticator(t, testRP, AlgES256, "7")
	a.counter = 5
	if status, out := e.do(t, call{method: "POST", path: "/api/webauthn/register/verify", p: &p,
		body: map[string]any{"ceremony": str(t, opts["ceremony"]), "credential": a.register(t, ch, attNone)}}); status != 201 {
		t.Fatalf("register: %d %v", status, out)
	}
	br := browserID(3)
	signIn := func(o assertOpts) int {
		ch, _ := e.signInOptions(t, br)
		status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", browser: br, body: map[string]any{"credential": a.assert(t, ch, o)}})
		return status
	}
	for _, c := range []struct {
		counter uint32
		want    int
	}{{5, 401}, {6, 200}, {6, 401}, {0, 401}, {100, 200}, {99, 401}} {
		o := assertOpts{counter: c.counter}
		if c.counter == 0 {
			o.authData = func(b []byte) []byte { b[33], b[34], b[35], b[36] = 0, 0, 0, 0; return b }
			o.counter = 101
		}
		if got := signIn(o); got != c.want {
			t.Fatalf("counter %d: %d, want %d", c.counter, got, c.want)
		}
	}
}

func TestMFASignIn(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	mine, _ := e.enrol(t, user(7), AlgES256, "")
	theirs, _ := e.enrol(t, user(8), AlgES256, "")
	br := browserID(4)
	e.pending.users[br] = 7
	ch, allow := e.signInOptions(t, br)
	if len(allow) != 1 || allow[0] != encodeB64URL(mine.id) {
		t.Fatalf("allowCredentials %v", allow)
	}
	// Another account's passkey does not complete this sign-in.
	if status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", browser: br, body: map[string]any{"credential": theirs.assert(t, ch, assertOpts{})}}); status != 401 {
		t.Fatalf("foreign passkey: %d", status)
	}
	ch, _ = e.signInOptions(t, br)
	none := ""
	status, out := e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", browser: br, body: map[string]any{"credential": mine.assert(t, ch, assertOpts{handle: &none})}})
	if status != 200 || str(t, out["continuation"]) != "/next" {
		t.Fatalf("mfa: %d %v", status, out)
	}
	if got := e.pending.completed; len(got) != 1 || got[0] != "7|passkey|PHISHING_RESISTANT" || len(e.direct.signins) != 0 {
		t.Fatalf("completed %v direct %v", got, e.direct.signins)
	}
	// An account without passkeys gets no options.
	e.pending.users[br] = 9
	if status, out := e.do(t, call{method: "POST", path: "/api/webauthn/auth/options", body: map[string]any{}, browser: br}); status != 409 || str(t, out["error"]) != "No passkey is available" {
		t.Fatalf("no passkey: %d %v", status, out)
	}
}

func TestSignInRateLimit(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	for i := range 10 {
		if status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/options", body: map[string]any{}, browser: browserID(i)}); status != 200 {
			t.Fatalf("request %d: %d", i, status)
		}
	}
	status, out := e.do(t, call{method: "POST", path: "/api/webauthn/auth/options", body: map[string]any{}, browser: browserID(99)})
	if status != 429 || str(t, out["error"]) != "Too many login attempts" {
		t.Fatalf("limit: %d %v", status, out)
	}
	if status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/options", body: map[string]any{}, browser: browserID(99), addr: "192.0.2.2"}); status != 200 {
		t.Fatal("other source limited")
	}
	for range 10 {
		e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", body: map[string]any{}, browser: browserID(1)})
	}
	if status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", body: map[string]any{}, browser: browserID(1)}); status != 429 {
		t.Fatalf("verify limit: %d", status)
	}
}

// TestConcurrentAnswers sends one answer many times at once: exactly one
// sign-in succeeds.
func TestConcurrentAnswers(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	e.http.Limits.Enabled = false
	a, _ := e.enrol(t, user(7), AlgES256, "")
	br := browserID(5)
	ch, _ := e.signInOptions(t, br)
	cred := a.assert(t, ch, assertOpts{})
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", browser: br, body: map[string]any{"credential": cred}}); status == 200 {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d sign-ins", ok.Load())
	}
	// Two browsers with the same counter value at once: one wins.
	a.counter = 41
	b1, b2 := browserID(6), browserID(7)
	ch1, _ := e.signInOptions(t, b1)
	ch2, _ := e.signInOptions(t, b2)
	c1 := a.assert(t, ch1, assertOpts{counter: 42})
	c2 := a.assert(t, ch2, assertOpts{counter: 42})
	ok.Store(0)
	for _, c := range []struct {
		b    string
		cred jsontext.Value
	}{{b1, c1}, {b2, c2}} {
		wg.Go(func() {
			if status, _ := e.do(t, call{method: "POST", path: "/api/webauthn/auth/verify", browser: c.b, body: map[string]any{"credential": c.cred}}); status == 200 {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("same counter accepted %d times", ok.Load())
	}
}

package auth

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/keyring"
	"github.com/bifrost0x/webssh/internal/store"
)

type testDeviceCookie struct{}

func (testDeviceCookie) Name() string { return "session_device" }
func (testDeviceCookie) Set(w http.ResponseWriter, v string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{Name: "session_device", Value: v, Expires: exp, HttpOnly: true})
}

type tightSettings struct{}

func (tightSettings) RegistrationEnabled(context.Context) (bool, error) { return false, nil }
func (tightSettings) LoginLimits(context.Context) (int, int, int, error) {
	return 3, 4, 128, nil
}

func newDeviceEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t, false)
	e.flow.Settings = tightSettings{}
	e.flow.Devices = &Devices{MAC: e.flow.MAC, Cookie: testDeviceCookie{}, Accounts: e.flow.Accounts, Now: e.clock.now}
	return e
}

func (b *browser) from(n int) *browser {
	b.ip = "198.51.100." + strconv.Itoa(n) + ":4000"
	return b
}

func signedIn(b *browser) bool { return b.cookies["session"] != "" }

// limited reports whether the last answer was the rate-limit flash.
func limited(e *env) bool {
	c := e.pages.last()
	return len(c.login.Flashes) == 1 && c.login.Flashes[0].Message == msgTooManyLogins
}

func TestKnownDeviceSkipsTheNameCeiling(t *testing.T) {
	t.Parallel()
	e := newDeviceEnv(t)
	e.createUser(t, "owner", "rightpass1")
	owner := e.browser()
	owner.do("POST", "/login", creds("owner", "rightpass1"))
	if !signedIn(owner) || owner.cookies["session_device"] == "" {
		t.Fatalf("no known-device cookie after the password step: %v", owner.cookies)
	}
	device := owner.cookies["session_device"]
	owner.do("POST", "/logout", nil)

	// A sender spread over many sources uses up the ceiling of the name.
	for i := range 4 {
		e.browser().from(10+i).do("POST", "/login", creds("owner", "wrong"))
		if limited(e) {
			t.Fatalf("attempt %d limited", i)
		}
	}
	e.browser().from(20).do("POST", "/login", creds("Owner ", "wrong"))
	if !limited(e) {
		t.Fatal("the name ceiling did not apply")
	}
	stranger := e.browser().from(21)
	stranger.do("POST", "/login", creds("owner", "rightpass1"))
	if signedIn(stranger) {
		t.Fatal("a browser without the cookie passed the ceiling")
	}
	// The known browser still signs in, from another source too.
	owner.from(30).do("POST", "/login", creds("owner", "rightpass1"))
	if !signedIn(owner) {
		t.Fatalf("the known browser is locked out: %+v", e.pages.last())
	}
	if owner.cookies["session_device"] == device {
		t.Fatal("the cookie was not renewed")
	}

	// A copied cookie gives a small budget of failures only.
	thief := e.browser()
	thief.cookies["session_device"] = owner.cookies["session_device"]
	for i := range DeviceFailureBudget {
		thief.from(40+i).do("POST", "/login", creds("owner", "wrong"))
		if limited(e) {
			t.Fatalf("failure %d within the budget limited", i)
		}
	}
	thief.from(50).do("POST", "/login", creds("owner", "rightpass1"))
	if signedIn(thief) || !limited(e) {
		t.Fatal("the cookie budget did not end the exemption")
	}
	// The per-source limit applies with the cookie as well.
	other := e.browser()
	other.cookies["session_device"] = owner.cookies["session_device"]
	for range 3 {
		other.from(60).do("POST", "/login", creds("nobody", "wrong"))
	}
	other.from(60).do("POST", "/login", creds("nobody", "wrong"))
	if !limited(e) {
		t.Fatal("per-source limit skipped")
	}
}

func TestKnownDeviceCookieChecks(t *testing.T) {
	t.Parallel()
	e := newDeviceEnv(t)
	acc := e.createUser(t, "owner", "rightpass1")
	e.createUser(t, "other", "rightpass1")
	d := e.flow.Devices
	w := httptest.NewRecorder()
	d.Remember(w, acc, " OWNER ")
	value := w.Result().Cookies()[0].Value
	if exp := w.Result().Cookies()[0].Expires; exp.Sub(e.clock.now()) != DeviceMaxAge {
		t.Fatalf("expiry %v", exp)
	}
	trusted := func(v, name string) bool {
		r := httptest.NewRequest("POST", "/login", nil)
		r.AddCookie(&http.Cookie{Name: "session_device", Value: v})
		return d.Trusted(r, name) != ""
	}
	if !trusted(value, "owner") || !trusted(value, "Owner") {
		t.Fatal("valid cookie refused")
	}
	if trusted(value, "other") || trusted(value, "") || trusted(value, "   ") {
		t.Fatal("cookie of another name accepted")
	}
	body, sig, _ := strings.Cut(strings.TrimPrefix(value, devicePrefix), ".")
	for _, bad := range []string{"", "v1.", value + "x", devicePrefix + body + "." + sig[:len(sig)-2] + "AA", "v2." + body + "." + sig,
		devicePrefix + body + "x." + sig, strings.Repeat("a", maxDeviceBytes+1)} {
		if trusted(bad, "owner") {
			t.Errorf("tampered cookie %q accepted", bad)
		}
	}
	// A cookie signed with another key is refused.
	ring, _ := keyring.Open([]byte("other"), bytes.Repeat([]byte{2}, keyring.MaterialSize))
	foreign := &Devices{MAC: ring, Cookie: testDeviceCookie{}, Accounts: e.flow.Accounts, Now: e.clock.now}
	w = httptest.NewRecorder()
	foreign.Remember(w, acc, "owner")
	if trusted(w.Result().Cookies()[0].Value, "owner") {
		t.Fatal("cookie of another installation accepted")
	}
	// Expiry.
	e.clock.add(DeviceMaxAge + time.Second)
	if trusted(value, "owner") {
		t.Fatal("expired cookie accepted")
	}
	e.clock.add(-DeviceMaxAge)
	if !trusted(value, "owner") {
		t.Fatal("cookie refused inside its lifetime")
	}
	// A password change, lock or factor reset raises the generation.
	if err := e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := e.flow.Accounts.PasswordChangedTx(t.Context(), tx, acc.ID, "h:new")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if trusted(value, "owner") {
		t.Fatal("cookie of an old generation accepted")
	}
	// A locked account's cookie is refused.
	w = httptest.NewRecorder()
	acc, _ = e.flow.Accounts.Get(t.Context(), acc.ID)
	d.Remember(w, acc, "owner")
	fresh := w.Result().Cookies()[0].Value
	if err := e.flow.DB.Write(t.Context(), func(tx *store.Tx) error {
		_, err := tx.ExecContext(t.Context(), `UPDATE accounts_users SET is_locked = 1 WHERE id = ?`, acc.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if trusted(fresh, "owner") {
		t.Fatal("cookie of a locked account accepted")
	}
	// Without Devices the flow works as before.
	var none *Devices
	none.Remember(httptest.NewRecorder(), acc, "owner")
	if none.Trusted(httptest.NewRequest("POST", "/", nil), "owner") != "" {
		t.Fatal("nil Devices trusted a browser")
	}
}

func FuzzDeviceCookie(f *testing.F) {
	ring, _ := keyring.Open([]byte("fuzz"), bytes.Repeat([]byte{3}, keyring.MaterialSize))
	d := &Devices{MAC: ring, Now: func() time.Time { return time.Unix(1_800_000_000, 0) }}
	f.Add(d.encode(devicePayload{Username: "u", UserID: 1, Nonce: "n", Issued: 1_800_000_000}))
	f.Add("v1.e30.")
	f.Add("v1..")
	f.Fuzz(func(t *testing.T, v string) {
		p, ok := d.decode(v)
		if ok && (p.UserID <= 0 || p.Nonce == "" || p.Username == "") {
			t.Fatalf("decoded an incomplete payload %+v", p)
		}
		if ok && d.encode(p) == "" {
			t.Fatal("re-encode failed")
		}
	})
}

package auth

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// While no account exists, the browser registration creates the
// administrator. A page whose DNS name an attacker rebinds to this server
// could do that from a visitor's browser, so the first account is refused
// unless the host is one FirstAccountHost trusts (finding #68). The page
// says why and the log says what to do; later accounts are not affected.
func TestFirstAccountNeedsATrustedHost(t *testing.T) {
	t.Parallel()
	for _, ongoing := range []bool{false, true} {
		e := newEnv(t, ongoing)
		var trusted atomic.Bool
		var logs syncBuffer
		e.flow.FirstAccountHost = func(*http.Request) bool { return trusted.Load() }
		e.flow.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		form := url.Values{"username": {"rebind"}, "password": {"password1"}, "confirm_password": {"password1"}}

		b := e.browser()
		b.do("GET", "/register", nil)
		if c := e.pages.last(); c.page != "register" || c.status != http.StatusForbidden ||
			len(c.form.Flashes) != 1 || !strings.Contains(c.form.Flashes[0].Message, "ALLOWED_HOSTS") {
			t.Fatalf("ongoing=%v: register page from an untrusted host: %+v", ongoing, c)
		}
		b.do("POST", "/register", form)
		if c := e.pages.last(); c.page != "register" || c.status != http.StatusForbidden {
			t.Fatalf("ongoing=%v: registration from an untrusted host: %+v", ongoing, c)
		}
		if has, _ := e.flow.Accounts.HasAccounts(t.Context()); has {
			t.Fatalf("ongoing=%v: the first account was created through an untrusted host", ongoing)
		}
		if !e.audit.has("REGISTRATION_FAILED:rebind") {
			t.Fatalf("ongoing=%v: audit %v", ongoing, e.audit.events)
		}
		if out := logs.String(); !strings.Contains(out, "level=WARN") || !strings.Contains(out, "ALLOWED_HOSTS") ||
			!strings.Contains(out, "create-admin") {
			t.Fatalf("ongoing=%v: log %q", ongoing, out)
		}

		trusted.Store(true)
		if rec := e.browser().do("POST", "/register", url.Values{"username": {"admin"}, "password": {"password1"},
			"confirm_password": {"password1"}}); rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
			t.Fatalf("ongoing=%v: registration from a trusted host: %d", ongoing, rec.Code)
		}
		if !ongoing {
			continue
		}
		// With open registration, later accounts register through any
		// host and do not become administrators.
		trusted.Store(false)
		late := e.browser()
		if rec := late.do("POST", "/register", form); rec.Code != http.StatusFound {
			t.Fatalf("later account from an untrusted host: %d %+v", rec.Code, e.pages.last())
		}
		if p := late.principal(t); p.IsAdmin || p.Username != "rebind" {
			t.Fatalf("later account %+v", p)
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

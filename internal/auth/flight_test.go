package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

func TestNewFlightIsRandomAndPythonSized(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	a, b := NewFlight(ProviderOIDC, PurposeSignIn, now), NewFlight(ProviderOIDC, PurposeSignIn, now)
	if len(a.State) != 43 || len(a.Nonce) != 43 || len(a.Verifier) != 86 {
		t.Fatalf("lengths %d %d %d, want 43 43 86", len(a.State), len(a.Nonce), len(a.Verifier))
	}
	if a.State == b.State || a.Nonce == b.Nonce || a.Verifier == b.Verifier || a.State == a.Nonce {
		t.Fatal("flight values repeat")
	}
}

// RFC 7636, appendix B.
func TestChallengeS256(t *testing.T) {
	t.Parallel()
	f := Flight{Verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"}
	if got := f.Challenge(); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge %q", got)
	}
	sum := sha256.Sum256([]byte(f.Verifier))
	if f.Challenge() != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("challenge is not unpadded base64url")
	}
}

func TestAccept(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	f := NewFlight(ProviderGitHub, PurposeLink, now)
	good := Callback{Code: "c", State: f.State}
	if err := f.Accept(good, now.Add(FlightTTL)); err != nil {
		t.Fatalf("valid callback: %v", err)
	}
	refused := map[string]struct {
		f   Flight
		cb  Callback
		now time.Time
	}{
		"other state":    {f, Callback{Code: "c", State: f.State + "x"}, now},
		"empty state":    {f, Callback{Code: "c"}, now},
		"no stored":      {Flight{IssuedAt: now}, Callback{Code: "c"}, now},
		"expired":        {f, good, now.Add(FlightTTL + time.Second)},
		"from the past":  {f, good, now.Add(-time.Second)},
		"no issue time":  {Flight{State: f.State}, good, now},
		"provider error": {f, Callback{Code: "c", State: f.State, Error: "access_denied"}, now},
		"no code":        {f, Callback{State: f.State}, now},
	}
	for name, c := range refused {
		if err := c.f.Accept(c.cb, c.now); !fault.Is(err, fault.AuthFailed) {
			t.Errorf("%s: %v, want auth_failed", name, err)
		}
	}
}

func TestParseCallback(t *testing.T) {
	t.Parallel()
	cb, err := ParseCallback(url.Values{"code": {"abc"}, "state": {"s"}, "other": {"x", "y"}})
	if err != nil || cb != (Callback{Code: "abc", State: "s"}) {
		t.Fatalf("ParseCallback = %+v, %v", cb, err)
	}
	for name, q := range map[string]url.Values{
		"two states": {"code": {"c"}, "state": {"a", "b"}},
		"long code":  {"code": {strings.Repeat("a", maxCallbackField+1)}, "state": {"s"}},
		"two errors": {"error": {"a", "b"}},
	} {
		if _, err := ParseCallback(q); !fault.Is(err, fault.AuthFailed) {
			t.Errorf("%s: %v, want auth_failed", name, err)
		}
	}
}

func FuzzParseCallback(f *testing.F) {
	f.Add("code=a&state=b")
	f.Add("state=a&state=b")
	f.Add("error=access_denied&state=%ff")
	now := time.Unix(1_700_000_000, 0)
	flight := Flight{State: "b", IssuedAt: now}
	f.Fuzz(func(t *testing.T, raw string) {
		q, err := url.ParseQuery(raw)
		if err != nil {
			return
		}
		cb, err := ParseCallback(q)
		if err != nil {
			return
		}
		if len(cb.Code) > maxCallbackField || len(cb.State) > maxCallbackField {
			t.Fatal("oversized field accepted")
		}
		if flight.Accept(cb, now) == nil && (cb.State != "b" || cb.Code == "" || cb.Error != "") {
			t.Fatalf("accepted %+v", cb)
		}
	})
}

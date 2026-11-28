package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type prefixSettings struct{ prefix int }

func (prefixSettings) RegistrationEnabled(context.Context) (bool, error) { return false, nil }
func (s prefixSettings) LoginLimits(context.Context) (int, int, int, error) {
	return 5, 100, s.prefix, nil
}

// The factor, step-up and IdP routes group IPv6 sources by
// ratelimit_ipv6_prefix like the sign-in forms (rate_limit_address).
func TestFactorLimitsUseIPv6Prefix(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		prefix  int
		limited bool
	}{{64, true}, {128, false}} {
		addr := "2001:db8::1"
		l := FactorLimits{Limiter: NewLimiter(), Enabled: true, Login: Rule{1, time.Minute}, Reauth: Rule{1, time.Minute},
			Settings: prefixSettings{tc.prefix}, ClientAddr: func(*http.Request) string { return addr }}
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/login", nil)
		if l.SourceLimited(r, "oidc_login") {
			t.Fatalf("prefix %d: first request limited", tc.prefix)
		}
		addr = "2001:db8::2"
		if got := l.SourceLimited(r, "oidc_login"); got != tc.limited {
			t.Errorf("prefix %d: second address of the /64 limited = %v, want %v", tc.prefix, got, tc.limited)
		}
		if got := l.ReauthLimited(r, 7, "stepup"); got {
			t.Errorf("prefix %d: first reauth limited", tc.prefix)
		}
		addr = "2001:db8::3"
		if got := l.ReauthLimited(r, 8, "stepup"); got != tc.limited {
			t.Errorf("prefix %d: reauth of another user from the /64 limited = %v, want %v", tc.prefix, got, tc.limited)
		}
	}
}

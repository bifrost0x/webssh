package config

import (
	"slices"
	"testing"
)

func TestOIDCValues(t *testing.T) {
	c, warns := mustLoad(t, map[string]string{
		"OIDC_ENABLED": "true", "OIDC_ISSUER": "https://idp.example/realm/", "OIDC_CLIENT_ID": " webssh ",
		"OIDC_CLIENT_SECRET_FILE": "/run/secrets/oidc", "OIDC_REDIRECT_URI": "https://ssh.example/oidc/callback",
		"OIDC_ALLOWED_SUBJECTS": "a, b,,a", "OIDC_ALLOWED_DOMAINS": "Example.ORG , lab.test",
		"OIDC_MFA_AMR_VALUES": "otp,mfa", "OIDC_STEP_UP_ACR_VALUES": "urn:mfa", "OIDC_LOGIN_RATE_LIMIT": "3 per minute",
	})
	o := c.OIDC
	slices.Sort(o.AllowedSubjects)
	slices.Sort(o.AllowedDomains)
	slices.Sort(o.MFAAMR)
	if !o.Enabled || o.Issuer != "https://idp.example/realm" || o.ClientID != "webssh" || o.ClientSecretFile != "/run/secrets/oidc" ||
		o.RedirectURI != "https://ssh.example/oidc/callback" || !slices.Equal(o.AllowedSubjects, []string{"a", "b"}) ||
		!slices.Equal(o.AllowedDomains, []string{"example.org", "lab.test"}) || !slices.Equal(o.MFAAMR, []string{"mfa", "otp"}) ||
		!slices.Equal(o.StepUpACR, []string{"urn:mfa"}) || o.LoginRateLimit != "3 per minute" {
		t.Fatalf("%+v", o)
	}
	if warningFor(warns, "", "OIDC_ENABLED") {
		t.Fatal("OIDC variables reported without effect")
	}
	if c, _ := mustLoad(t, nil); c.OIDC.Enabled || c.OIDC.LoginRateLimit != "10 per minute" {
		t.Fatalf("defaults %+v", c.OIDC)
	}
}

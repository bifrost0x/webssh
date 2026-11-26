package e2eseed

import (
	"context"
	json "encoding/json/v2"
	"fmt"
)

// Identities links external identities to seeded accounts.
type Identities interface {
	// LinkOIDC links the OIDC identity (issuer, subject) to the account.
	LinkOIDC(ctx context.Context, userID int64, issuer, subject string) error
}

// identityProvider is the provider member of an external identity.
func identityProvider(e OwnedEntry) string { return member(e, "provider") }

func member(e OwnedEntry, name string) string {
	var s string
	if raw, ok := e.Members[name]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// unappliedIdentities reports whether the seed has external identities of
// providers this build does not apply (LDAP, GitHub).
func (s *Seed) unappliedIdentities() bool {
	for _, e := range s.ExternalIdentities {
		if identityProvider(e) != "oidc" {
			return true
		}
	}
	return false
}

// applyIdentities links the OIDC identities of the seed.
func applyIdentities(ctx context.Context, s *Seed, st Stores, users map[string]int64) error {
	for _, e := range s.ExternalIdentities {
		if identityProvider(e) != "oidc" {
			continue
		}
		issuer, subject := member(e, "issuer"), member(e, "subject")
		if issuer == "" || subject == "" {
			return fmt.Errorf("OIDC identity of %s: issuer and subject are required", e.Account)
		}
		if err := st.Identities.LinkOIDC(ctx, users[e.Account], issuer, subject); err != nil {
			return fmt.Errorf("OIDC identity of %s: %w", e.Account, err)
		}
	}
	return nil
}

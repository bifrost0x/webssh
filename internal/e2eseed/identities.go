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
	// LinkGitHub links the GitHub identity (numeric id, login) to the
	// account; the account stays local, as in run_app.py.
	LinkGitHub(ctx context.Context, userID int64, githubUserID, login string) error
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

// applyIdentities links the OIDC and GitHub identities of the seed, as
// run_app.py does; another provider is an error there too.
func applyIdentities(ctx context.Context, s *Seed, st Stores, users map[string]int64) error {
	for _, e := range s.ExternalIdentities {
		switch provider := identityProvider(e); provider {
		case "oidc":
			issuer, subject := member(e, "issuer"), member(e, "subject")
			if issuer == "" || subject == "" {
				return fmt.Errorf("OIDC identity of %s: issuer and subject are required", e.Account)
			}
			if err := st.Identities.LinkOIDC(ctx, users[e.Account], issuer, subject); err != nil {
				return fmt.Errorf("OIDC identity of %s: %w", e.Account, err)
			}
		case "github":
			id, login := member(e, "github_user_id"), member(e, "login")
			if id == "" || login == "" {
				return fmt.Errorf("GitHub identity of %s: github_user_id and login are required", e.Account)
			}
			if err := st.Identities.LinkGitHub(ctx, users[e.Account], id, login); err != nil {
				return fmt.Errorf("GitHub identity of %s: %w", e.Account, err)
			}
		default:
			return fmt.Errorf("external identity of %s: unknown provider %q", e.Account, provider)
		}
	}
	return nil
}

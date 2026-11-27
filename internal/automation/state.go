package automation

import (
	"context"
	"encoding/json/jsontext"
	"slices"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/vault"
)

func slicesDelete(books []Runbook, id string) []Runbook {
	return slices.DeleteFunc(books, func(b Runbook) bool { return b.ID == id })
}

// emptyVault is the state of the passphrase vault, which runs no longer
// use (D-06): saved passwords replace it.
var emptyVault = pyjson.Object([]pyjson.Member{
	{Name: "exists", Value: jsonBool(false)}, {Name: "unlocked", Value: jsonBool(false)},
	{Name: "expires_in", Value: jsontext.Value("0")}, {Name: "credentials", Value: jsontext.Value("[]")},
})

// credentialStatus is credential_status of a password hop; key hops are
// ready.
func (s *Service) credentialStatus(ctx context.Context, userID int64, h *hop, credentials bool) string {
	if h.AuthType != "password" {
		return "ready"
	}
	if !credentials {
		return string(vault.StatusDisabled)
	}
	st, _, err := s.o.Passwords.Binding(ctx, userID, h.ResourceID, h.Target)
	switch {
	case err != nil:
		return string(vault.StatusMissing)
	case st == vault.StatusReady || st == vault.StatusChanged || st == vault.StatusDisabled:
		return string(st)
	}
	return string(vault.StatusMissing)
}

// State is GET /api/automation/state.
func (s *Service) State(ctx context.Context, userID int64) (jsontext.Value, error) {
	books, err := s.runbooks(ctx, userID)
	if err != nil {
		return nil, err
	}
	inv, err := s.inventory(ctx, userID)
	if err != nil {
		return nil, err
	}
	credentials, err := s.o.Switches.CredentialsEnabled(ctx)
	if err != nil {
		credentials = false
	}
	bookValues := make([]jsontext.Value, len(books))
	for i, b := range books {
		bookValues[i] = b.Value()
	}
	profiles := make([]jsontext.Value, 0, len(inv.profiles))
	for _, p := range inv.profiles {
		m := p.display()
		m = append(m,
			pyjson.Member{Name: "auth_type", Value: rawMember(p.Page, "auth_type")},
			pyjson.Member{Name: "credential_status", Value: pyjson.String(s.credentialStatus(ctx, userID, &p, credentials))},
			pyjson.Member{Name: "supported", Value: jsonBool(inv.targetSupported(p))})
		if r := inv.route(p); r != nil {
			m = append(m,
				pyjson.Member{Name: "via", Value: rawMember(r.Page, "name")},
				pyjson.Member{Name: "route_id", Value: pyjson.String(r.ResourceID)},
				pyjson.Member{Name: "route_auth_type", Value: rawMember(r.Page, "auth_type")},
				pyjson.Member{Name: "route_credential_status", Value: pyjson.String(s.credentialStatus(ctx, userID, r, credentials))})
		}
		if p.SOCKS {
			m = append(m,
				pyjson.Member{Name: "socks_proxy_id", Value: rawMember(p.Page, "socks_proxy_id")},
				pyjson.Member{Name: "unsupported_reason", Value: pyjson.String("SOCKS5 routes are not supported for automation yet")})
		}
		profiles = append(profiles, pyjson.Object(m))
	}
	return pyjson.Object([]pyjson.Member{
		{Name: "enabled", Value: jsonBool(true)},
		{Name: "credentials_enabled", Value: jsonBool(credentials)},
		{Name: "runbooks", Value: pyjson.Array(bookValues)},
		{Name: "profiles", Value: pyjson.Array(profiles)},
		{Name: "vault", Value: emptyVault},
	}), nil
}

func rawMember(m []pyjson.Member, name string) jsontext.Value {
	if v := member(m, name); v != nil {
		return v
	}
	return jsontext.Value("null")
}

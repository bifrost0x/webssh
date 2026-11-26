package auth_test

import (
	"net/url"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/auth"
	"github.com/bifrost0x/webssh/internal/auth/authtest"
	"github.com/bifrost0x/webssh/internal/fault"
)

// A consumer of the external identity contract signs in, links and
// provisions against the fakes; the refusals are those of the contract.
func TestExternalSignInAgainstFakes(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	now := time.Unix(1_700_000_000, 0)
	idp := &authtest.Provider{ProviderName: auth.ProviderOIDC, Now: func() time.Time { return now }}
	links := &authtest.Links{PerAccount: 0}

	f := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, now)
	redirect, err := idp.Begin(ctx, f)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Query().Get("state") != f.State || u.Query().Get("code_challenge") != f.Challenge() {
		t.Fatalf("redirect %q: %v", redirect, err)
	}
	idp.Issue("code-1", auth.Identity{Issuer: "https://idp.example", Subject: "sub-1", Username: "alice"})
	cb, _ := auth.ParseCallback(url.Values{"code": {"code-1"}, "state": {f.State}})
	id, err := idp.Complete(ctx, f, cb)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := idp.Complete(ctx, f, cb); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("code replay: %v", err)
	}
	if _, err := links.Account(ctx, id); !fault.Is(err, fault.NotFound) {
		t.Fatalf("unlinked identity: %v", err)
	}
	if _, err := links.Provision(ctx, id); !fault.Is(err, fault.Forbidden) {
		t.Fatalf("provisioning without a policy: %v", err)
	}
	if _, err := links.LinkTx(ctx, nil, 7, id); err != nil {
		t.Fatal(err)
	}
	if uid, err := links.Account(ctx, id); err != nil || uid != 7 {
		t.Fatalf("Account = %d, %v", uid, err)
	}
	// The same identity never moves to a second account.
	if _, err := links.LinkTx(ctx, nil, 8, id); !fault.Is(err, fault.Conflict) {
		t.Fatalf("second link: %v", err)
	}
	other := auth.NewFlight(auth.ProviderOIDC, auth.PurposeSignIn, now)
	idp.Issue("code-2", id)
	if _, err := idp.Complete(ctx, f, auth.Callback{Code: "code-2", State: other.State}); !fault.Is(err, fault.AuthFailed) {
		t.Fatalf("state of another flight: %v", err)
	}
}

func TestLinksPerAccountAndProvision(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	links := &authtest.Links{PerAccount: 1, NewAccount: func(auth.Identity) (int64, error) { return 9, nil }}
	a := auth.Identity{Provider: auth.ProviderGitHub, Subject: "1"}
	uid, err := links.Provision(ctx, a)
	if err != nil || uid != 9 {
		t.Fatalf("Provision = %d, %v", uid, err)
	}
	if _, err := links.LinkTx(ctx, nil, 9, auth.Identity{Provider: auth.ProviderGitHub, Subject: "2"}); !fault.Is(err, fault.Conflict) {
		t.Fatalf("second GitHub identity on one account: %v", err)
	}
	list, _ := links.List(ctx, 9)
	if len(list) != 1 || !list[0].Provisioned {
		t.Fatalf("List = %+v", list)
	}
	if err := links.Unlink(ctx, 8, list[0].ID); !fault.Is(err, fault.NotFound) {
		t.Fatalf("unlink from another account: %v", err)
	}
	if err := links.Unlink(ctx, 9, list[0].ID); err != nil {
		t.Fatal(err)
	}
}

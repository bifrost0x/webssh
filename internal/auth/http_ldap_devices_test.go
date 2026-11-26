package auth

import (
	"context"
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// fakeDirectory accepts one name and password.
type fakeDirectory struct {
	name, password string
	userID         int64
}

func (fakeDirectory) Name() string { return "ldap" }

func (d fakeDirectory) Authenticate(_ context.Context, username, secret string) (int64, error) {
	if username != d.name || secret != d.password {
		return 0, fault.New(fault.AuthFailed, "")
	}
	return d.userID, nil
}

// The directory sign-in makes the browser a known device and honours the
// cookie like the local sign-in (ldap_routes.py): a browser with the
// cookie passes the name ceiling of the endpoint ldap_login.
func TestDirectorySignInKnownDevice(t *testing.T) {
	t.Parallel()
	e := newDeviceEnv(t)
	acc := e.createUser(t, "owner", "localpass1")
	d := &DirectorySignIn{Flow: e.flow, Provider: fakeDirectory{"owner", "dirpass1", acc.ID}, Rule: Rule{Limit: 1000, Window: time.Minute}}
	d.Register(e.mux)
	owner := e.browser()
	owner.do("POST", PathLDAPLogin, creds("owner", "dirpass1"))
	if !signedIn(owner) || owner.cookies["session_device"] == "" {
		t.Fatalf("no known-device cookie after the directory sign-in: %v", owner.cookies)
	}
	device := owner.cookies["session_device"]
	owner.do("POST", "/logout", nil)

	for i := range 4 {
		e.browser().from(10+i).do("POST", PathLDAPLogin, creds("owner", "wrong"))
	}
	stranger := e.browser().from(21)
	stranger.do("POST", PathLDAPLogin, creds("owner", "dirpass1"))
	if signedIn(stranger) {
		t.Fatal("a browser without the cookie passed the ceiling")
	}
	owner.from(30).do("POST", PathLDAPLogin, creds("owner", "dirpass1"))
	if !signedIn(owner) {
		t.Fatal("the known browser is locked out of the directory sign-in")
	}
	if owner.cookies["session_device"] == device {
		t.Fatal("the cookie was not renewed")
	}
}

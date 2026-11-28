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

// spellingDirectory matches every spelling of a name to one entry, as a
// directory's caseIgnoreMatch does for full-width and mathematical
// letters, and reserves the attempt per entry like internal/auth/ldap.
type spellingDirectory struct {
	flow     *Flow
	password string
	userID   int64
}

func (spellingDirectory) Name() string { return "ldap" }

func (d spellingDirectory) Authenticate(ctx context.Context, _, secret string) (int64, error) {
	release, ok := d.flow.ReserveSubjectAttempt(ctx, "ldap_login", "corp\x00uuid-owner")
	if !ok {
		return 0, fault.New(fault.RateLimited, "")
	}
	if secret != d.password {
		return 0, fault.New(fault.AuthFailed, "")
	}
	release()
	return d.userID, nil
}

// Spellings of one directory name have their own name buckets; the
// ceiling per name still holds for the directory entry they all match.
// A browser with a known-device cookie passes it.
func TestDirectorySignInCeilingPerEntry(t *testing.T) {
	t.Parallel()
	e := newDeviceEnv(t) // name ceiling 4 per minute
	acc := e.createUser(t, "owner", "localpass1")
	d := &DirectorySignIn{Flow: e.flow, Provider: spellingDirectory{e.flow, "dirpass1", acc.ID}, Rule: Rule{Limit: 1000, Window: time.Minute}}
	d.Register(e.mux)
	owner := e.browser()
	owner.do("POST", PathLDAPLogin, creds("owner", "dirpass1"))
	if !signedIn(owner) {
		t.Fatal("owner not signed in")
	}
	owner.do("POST", "/logout", nil)
	spellings := []string{"ｏwner", "oｗner", "owｎer", "owneｒ"}
	for i, name := range spellings {
		e.browser().from(10+i).do("POST", PathLDAPLogin, creds(name, "wrong"))
	}
	stranger := e.browser().from(30)
	stranger.do("POST", PathLDAPLogin, creds("ｏｗner", "dirpass1"))
	if signedIn(stranger) || e.pages.last().login.LDAPError != msgTooManyLogins {
		t.Fatal("a new spelling passed the ceiling of the directory entry")
	}
	owner.from(31).do("POST", PathLDAPLogin, creds("owner", "dirpass1"))
	if !signedIn(owner) {
		t.Fatal("the known browser is locked out")
	}
}

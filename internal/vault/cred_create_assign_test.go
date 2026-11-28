package vault

import (
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// savedPassword stores a password without an assignment and returns its id.
func (r *credRig) savedPassword(t *testing.T, name string) string {
	t.Helper()
	p := principaltest.User(1)
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"name": name, "password": name + "-pw"}); err != nil {
		t.Fatal(err)
	}
	return r.state(t, p).credential(name)
}

func (r *credRig) resourceCount(t *testing.T) int {
	t.Helper()
	recs, err := r.stores.Records(t.Context(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return len(recs.Profiles) + len(recs.JumpHosts) + len(recs.SOCKSProxies) + len(recs.SMBShares)
}

func (r *credRig) assignments(t *testing.T) int {
	t.Helper()
	n := 0
	for _, c := range r.state(t, principaltest.User(1)).Credentials {
		n += len(c.Uses)
	}
	return n
}

var newResources = map[string]map[string]any{
	"ssh":   {"name": "Box", "host": "box.example", "port": 22, "username": "root", "auth_type": "password"},
	"jump":  {"name": "Bastion", "host": "jump.example", "port": 22, "username": "u", "auth_type": "password"},
	"socks": {"name": "Proxy", "host": "socks.example", "port": 1080, "username": "u", "auth_type": "password"},
}

// A new resource with a saved password binds that secret to a new
// destination: the step-up comes before anything is stored, and without it
// neither the resource nor the assignment exists.
func TestCreateForResourceWithSavedPasswordNeedsStepUpFirst(t *testing.T) {
	t.Parallel()
	for kind, resource := range newResources {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()
			r := newCredRig(t)
			p := principaltest.User(1)
			id := r.savedPassword(t, "Shared")
			req := map[string]any{"resource_kind": kind, "confirm_target": true, "credential_id": id, "resource": resource}
			for grant, want := range map[string]fault.Code{"": fault.StepUpRequired, "forged-grant": fault.StepUpRequired} {
				_, err := r.doGrant(t, p, MethodCreateForResource, "", req, grant)
				if codeOf(err) != want {
					t.Fatalf("grant %q: %v, want %s", grant, err, want)
				}
				if n := r.resourceCount(t); n != 0 {
					t.Fatalf("grant %q: %d resources stored before the step-up", grant, n)
				}
				if n := r.assignments(t); n != 0 {
					t.Fatalf("grant %q: %d assignments stored before the step-up", grant, n)
				}
			}
			out, err := r.doGrant(t, p, MethodCreateForResource, "", req, "issue")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(out), `"resource":{"id":"new1"`) {
				t.Errorf("result %s", out)
			}
			resourceID := map[string]string{"ssh": "new1", "jump": "jump:new1", "socks": "socks:new1"}[kind]
			if s, c := r.state(t, p).profile(resourceID); s != "ready" || c != id {
				t.Errorf("new %s: status %q, credential %q, want ready %s", kind, s, c, id)
			}
			if n := len(r.state(t, p).Credentials); n != 1 {
				t.Errorf("%d passwords, want the one saved password", n)
			}
		})
	}
}

// The resource and its assignment are stored in one transaction: when the
// assignment fails, the resource is not stored either.
func TestCreateForResourceStoresNothingWhenTheAssignmentFails(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	p := principaltest.User(1)
	_, err := r.doGrant(t, p, MethodCreateForResource, "", map[string]any{"resource_kind": "ssh", "confirm_target": true,
		"credential_id": "missing-password", "resource": newResources["ssh"]}, "issue")
	if codeOf(err) != fault.NotFound {
		t.Fatalf("unknown saved password: %v", err)
	}
	if n := r.resourceCount(t); n != 0 {
		t.Fatalf("%d resources stored without their assignment", n)
	}
	if r.stores.rolledBack != 1 {
		t.Errorf("the resource was not rolled back in its transaction (%d)", r.stores.rolledBack)
	}
	// A request that mixes a saved password with a new one is refused.
	id := r.savedPassword(t, "Shared")
	_, err = r.doGrant(t, p, MethodCreateForResource, "", map[string]any{"resource_kind": "ssh", "confirm_target": true,
		"credential_id": id, "name": "Other", "password": "other-pw", "resource": newResources["ssh"]}, "issue")
	if codeOf(err) != fault.InvalidRequest {
		t.Fatalf("saved and new password together: %v", err)
	}
	if n := r.resourceCount(t); n != 0 {
		t.Fatalf("%d resources stored", n)
	}
}

func TestCreateForResourceKeepsTheNameConflict(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	r.stores.refuse = fault.New(fault.DuplicateName, "taken")
	_, err := r.do(t, principaltest.User(1), MethodCreateForResource, "", map[string]any{"resource_kind": "ssh",
		"confirm_target": true, "name": "Box", "password": "box-pw", "resource": newResources["ssh"]})
	if codeOf(err) != fault.DuplicateName {
		t.Fatalf("taken name: %v, want duplicate_name", err)
	}
}

func TestStateAnnouncesAssignOnCreate(t *testing.T) {
	t.Parallel()
	r := newCredRig(t)
	raw, err := r.svc.State(as(principaltest.User(1)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"save_with_assignment":true`) {
		t.Errorf("state %s", raw)
	}
}

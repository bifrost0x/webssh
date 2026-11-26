package vault

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

// TestFingerprintMatchesPython checks Fingerprint against values computed
// by profile_fingerprint of app/automation_store.py for the same records.
func TestFingerprintMatchesPython(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile("testdata/fingerprint-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Record struct {
			ID               *string `json:"id"`
			Kind             string  `json:"kind"`
			Host             *string `json:"host"`
			Port             *int64  `json:"port"`
			Username         *string `json:"username"`
			AuthType         *string `json:"auth_type"`
			KeyID            *string `json:"key_id"`
			JumpHostID       *string `json:"jump_host_id"`
			SOCKSProxyID     *string `json:"socks_proxy_id"`
			RemoteDNS        *bool   `json:"remote_dns"`
			Domain           *string `json:"domain"`
			Share            *string `json:"share"`
			RouteFingerprint string  `json:"route_fingerprint"`
		} `json:"record"`
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 10 {
		t.Fatalf("only %d vectors", len(vectors))
	}
	for i, v := range vectors {
		r := v.Record
		got := Fingerprint(Target{
			ID: r.ID, Kind: ResourceKind(r.Kind), Host: r.Host, Port: r.Port, Username: r.Username,
			AuthType: r.AuthType, KeyID: r.KeyID, JumpHostID: r.JumpHostID, SOCKSProxyID: r.SOCKSProxyID,
			RemoteDNS: r.RemoteDNS, Domain: r.Domain, Share: r.Share, RouteFingerprint: r.RouteFingerprint,
		})
		if got != v.Fingerprint {
			t.Errorf("vector %d: Fingerprint = %s, want %s", i, got, v.Fingerprint)
		}
	}
}

func TestFingerprintBindsTheTarget(t *testing.T) {
	t.Parallel()
	host, other := "a.example", "b.example"
	port := int64(22)
	base := Target{Kind: ResourceSSH, Host: &host, Port: &port}
	moved := base
	moved.Host = &other
	routed := base
	routed.RouteFingerprint = Fingerprint(base)
	if Fingerprint(base) == Fingerprint(moved) || Fingerprint(base) == Fingerprint(routed) {
		t.Error("a changed host or route keeps the fingerprint")
	}
}

func TestResourceIDs(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		kind ResourceKind
		rec  string
	}{{ResourceSSH, "p1"}, {ResourceJump, "j1"}, {ResourceSOCKS, "s1"}, {ResourceSMB, "x"}} {
		id := ResourceID(c.kind, c.rec)
		kind, rec, err := ParseResourceID(id)
		if err != nil || kind != c.kind || rec != c.rec {
			t.Errorf("round trip of %s = %s, %s, %v", id, kind, rec, err)
		}
	}
	for _, bad := range []string{"", "jump:", "ftp:x", "smb:"} {
		if _, _, err := ParseResourceID(bad); !fault.Is(err, fault.InvalidTargets) {
			t.Errorf("ParseResourceID(%q) = %v", bad, err)
		}
	}
}

type resources map[string]Target

func (r resources) Resource(_ context.Context, _ int64, id string) (Target, bool, error) {
	t, ok := r[id]
	return t, ok, nil
}

var _ Resources = resources(nil)

// statusOf is the assignment status as VA1 computes it on the contract.
func statusOf(ctx context.Context, r Resources, userID int64, a *Assignment, resourceID string) (Status, error) {
	if a == nil {
		return StatusMissing, nil
	}
	t, found, err := r.Resource(ctx, userID, resourceID)
	if err != nil || !found {
		return StatusMissing, err
	}
	if Fingerprint(t) != a.Fingerprint {
		return StatusChanged, nil
	}
	return StatusReady, nil
}

func TestStatusOnTheContract(t *testing.T) {
	t.Parallel()
	host := "a.example"
	target := Target{Kind: ResourceSSH, Host: &host}
	r := resources{"p1": target}
	a := &Assignment{ResourceID: "p1", CredentialID: "c1", Fingerprint: Fingerprint(target)}
	for _, c := range []struct {
		a    *Assignment
		id   string
		want Status
	}{{a, "p1", StatusReady}, {nil, "p1", StatusMissing}, {a, "gone", StatusMissing}} {
		if got, err := statusOf(t.Context(), r, 1, c.a, c.id); err != nil || got != c.want {
			t.Errorf("statusOf(%s) = %s, %v; want %s", c.id, got, err, c.want)
		}
	}
	other := "b.example"
	r["p1"] = Target{Kind: ResourceSSH, Host: &other}
	if got, _ := statusOf(t.Context(), r, 1, a, "p1"); got != StatusChanged {
		t.Errorf("changed target = %s", got)
	}
}

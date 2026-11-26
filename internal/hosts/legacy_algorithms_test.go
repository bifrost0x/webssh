package hosts

import (
	"encoding/json/jsontext"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// The per-host opt-in for the legacy SSH algorithms (D-01): saved with a
// host or jump host, kept by a save without the field, carried to the hop.
func TestLegacyAlgorithmsOptIn(t *testing.T) {
	s := seeded(t, Legacy{})
	ctx := t.Context()
	jump, err := s.SaveJumpHost(ctx, oracleUser, protocol.HostsJumpSave{Name: v(`"old"`), Host: v(`"old.example"`),
		Username: v(`"j"`), AuthType: v(`"password"`), LegacyAlgorithms: v(`true`)})
	if err != nil {
		t.Fatal(err)
	}
	jumpID := field(t, jump, "id")
	save := protocol.HostsProfileSave{Name: v(`"Old"`), Host: v(`"old.example"`), Username: v(`"u"`),
		AuthType: v(`"password"`), JumpHostID: v(jumpID), LegacyAlgorithms: v(`true`)}
	out, err := s.SaveProfile(ctx, oracleUser, save)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"legacy_algorithms":true`) {
		t.Fatalf("saved host does not show the opt-in: %s", out)
	}
	id := field(t, out, "id")
	tgt, err := s.Resolve(ctx, oracleUser, strings.Trim(id, `"`))
	if err != nil || !tgt.Hop.Legacy || len(tgt.Jumps) != 1 || !tgt.Jumps[0].Legacy {
		t.Fatalf("resolved %+v, %v", tgt, err)
	}
	// A save without the field keeps it, false removes it.
	if _, err := s.SaveProfile(ctx, oracleUser, protocol.HostsProfileSave{ID: v(id), Name: v(`"Old"`), Host: v(`"old.example"`),
		Username: v(`"u"`), AuthType: v(`"password"`)}); err != nil {
		t.Fatal(err)
	}
	if tgt, _ := s.Resolve(ctx, oracleUser, strings.Trim(id, `"`)); !tgt.Hop.Legacy {
		t.Fatal("a save without the field dropped the opt-in")
	}
	if _, err := s.SaveProfile(ctx, oracleUser, protocol.HostsProfileSave{ID: v(id), Name: v(`"Old"`), Host: v(`"old.example"`),
		Username: v(`"u"`), AuthType: v(`"password"`), LegacyAlgorithms: v(`false`)}); err != nil {
		t.Fatal(err)
	}
	if tgt, _ := s.Resolve(ctx, oracleUser, strings.Trim(id, `"`)); tgt.Hop.Legacy {
		t.Fatal("false kept the opt-in")
	}
	for _, bad := range []string{`"true"`, `1`, `{}`} {
		save.LegacyAlgorithms = v(bad)
		if _, err := s.SaveProfile(ctx, oracleUser, save); code(err) != fault.ValidationError {
			t.Errorf("profile %s: %v", bad, err)
		}
		if _, err := s.SaveJumpHost(ctx, oracleUser, protocol.HostsJumpSave{Name: v(`"x"`), Host: v(`"x.example"`),
			Username: v(`"j"`), AuthType: v(`"password"`), LegacyAlgorithms: v(bad)}); code(err) != fault.ValidationError {
			t.Errorf("jump host %s: %v", bad, err)
		}
	}
	// Hosts without the field (every migrated one) do not opt in.
	if tgt, err := s.Resolve(ctx, oracleUser, "0296e087-7c43-42d2-acb0-6703e8f44957"); err != nil || tgt.Hop.Legacy || tgt.Jumps[0].Legacy {
		t.Fatalf("migrated host: %+v %v", tgt, err)
	}
}

func field(t *testing.T, rec jsontext.Value, name string) string {
	t.Helper()
	dec := jsontext.NewDecoder(strings.NewReader(string(rec)))
	if _, err := dec.ReadToken(); err != nil {
		t.Fatal(err)
	}
	for dec.PeekKind() != '}' {
		k, err := dec.ReadToken()
		if err != nil {
			t.Fatal(err)
		}
		key := k.String()
		val, err := dec.ReadValue()
		if err != nil {
			t.Fatal(err)
		}
		if key == name {
			return string(val)
		}
	}
	t.Fatalf("no %s in %s", name, rec)
	return ""
}

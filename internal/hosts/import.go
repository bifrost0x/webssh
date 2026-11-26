package hosts

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"

	"github.com/bifrost0x/webssh/internal/store"
)

// Legacy holds the saved connection data of one user as the migration
// read it from the Python stores, each record lifted to the current store
// version (schema 3 for profiles, 2 for jump hosts and SOCKS5 proxies) in
// memory and otherwise untouched. WorkspacePresets is the
// workspace_presets value of settings.json, nil when the key is absent.
type Legacy struct {
	Profiles         []jsontext.Value
	JumpHosts        []jsontext.Value
	SOCKSProxies     []jsontext.Value
	WorkspacePresets jsontext.Value
}

// ImportReport says what the import noticed. Nothing in it stops the
// migration.
type ImportReport struct {
	// DroppedFacts counts identity facts Python itself drops when it loads
	// the store (_drop_invalid_stored_facts).
	DroppedFacts int
	// OverLimit names the stores with more records than the current limit;
	// they are kept whole and can only shrink.
	OverLimit []string
}

// ErrInvalidLegacy marks a record Python's own validator refuses; the
// migration stops for the whole installation (migration spec, common
// rules).
var ErrInvalidLegacy = errors.New("hosts: legacy record is invalid")

// Import stores the saved connection data of owner, replacing what Go
// holds for that user. It runs in the migration's transaction.
func Import(ctx context.Context, tx *store.Tx, owner int64, in Legacy, limits Limits) (ImportReport, error) {
	var report ImportReport
	profiles, err := importRecords(in.Profiles, "profile", func(r *record) bool {
		report.DroppedFacts += dropInvalidFacts(r)
		return validProfile(r)
	})
	if err != nil {
		return report, err
	}
	jumps, err := importRecords(in.JumpHosts, "jump host", validJumpHost)
	if err != nil {
		return report, err
	}
	socks, err := importRecords(in.SOCKSProxies, "SOCKS proxy", validSOCKSProxy)
	if err != nil {
		return report, err
	}
	seen := map[string]bool{}
	for i := range socks {
		id := socks[i].text("id")
		if seen[id] {
			return report, fmt.Errorf("%w: SOCKS proxy IDs are not unique", ErrInvalidLegacy)
		}
		seen[id] = true
	}
	all := stores{"profiles": profiles, "jump_hosts": jumps, "socks_proxies": socks}
	for _, k := range allKinds {
		if len(all[k.key]) > k.maxRecords(limits) {
			report.OverLimit = append(report.OverLimit, k.key)
		}
		if err := replace(ctx, tx, k.table, owner, all[k.key]); err != nil {
			return report, err
		}
	}
	if len(in.WorkspacePresets) > 0 {
		presets, err := canonical(in.WorkspacePresets)
		if err != nil || !validPresets(presets) {
			return report, fmt.Errorf("%w: workspace presets", ErrInvalidLegacy)
		}
		if err := storePresets(ctx, tx, owner, presets); err != nil {
			return report, err
		}
	}
	return report, nil
}

func importRecords(raw []jsontext.Value, what string, valid func(*record) bool) ([]record, error) {
	out := make([]record, 0, len(raw))
	for i, v := range raw {
		r, err := parseRecord(v)
		if err != nil {
			return nil, fmt.Errorf("%w: %s %d: %w", ErrInvalidLegacy, what, i, err)
		}
		if !valid(&r) {
			return nil, fmt.Errorf("%w: %s %d", ErrInvalidLegacy, what, i)
		}
		out = append(out, r)
	}
	return out, nil
}

// Export returns what Go holds for owner in the form Import takes, for the
// migration's verification.
func Export(ctx context.Context, tx *store.Tx, owner int64) (Legacy, error) {
	var out Legacy
	for _, k := range allKinds {
		records, err := load(ctx, tx, k.table, owner)
		if err != nil {
			return Legacy{}, err
		}
		values := encodeAll(records)
		switch k.key {
		case "profiles":
			out.Profiles = values
		case "jump_hosts":
			out.JumpHosts = values
		default:
			out.SOCKSProxies = values
		}
	}
	presets, found, err := loadPresets(ctx, tx, owner)
	if err != nil {
		return Legacy{}, err
	}
	if found {
		out.WorkspacePresets = presets
	}
	return out, nil
}

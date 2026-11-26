package settings

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"maps"
	"slices"

	"github.com/bifrost0x/webssh/internal/store"
)

// Settings the upgrade derives from the behaviour of the Python release
// (migration spec, section 6, decision D-01). An installation without a
// row gets the secure default of this release; the upgrade writes the
// previous behaviour as an explicit, visible setting and lists it in the
// migration report. The keys contain a dot, which no key of the legacy
// app_settings.json does.
const (
	// PolicyDiscovery grants host discovery per role (D-18, D-29). The
	// value is an object of role names to booleans. HOST_DISCOVERY_ENABLED
	// stays the ceiling. Default: no role but administrators.
	PolicyDiscovery = "permission.hosts.discovery"
	// PolicyReachability grants the overview reachability check per role
	// (D-27), same form and default.
	PolicyReachability = "permission.hosts.reachability"
	// PolicyOriginIgnoreScheme compares only host and port of a realtime
	// origin with the application's own, for installations behind a
	// TLS-terminating proxy that is not trusted (K6/A1). Default false.
	PolicyOriginIgnoreScheme = "origin.ignore_scheme"
	// PolicyLegacySSHAlgorithms offers ssh-rsa with SHA-1, SHA-1 key
	// exchange, aes128-cbc and 3des-cbc to every host at the lowest
	// priority, as paramiko did (K2, D-01). Default false: new
	// installations enable them per host.
	PolicyLegacySSHAlgorithms = "ssh.legacy_algorithms"
)

// RoleUser is the role of every account that is not an administrator.
const RoleUser = "user"

var policyKeys = []string{PolicyDiscovery, PolicyReachability, PolicyOriginIgnoreScheme, PolicyLegacySSHAlgorithms}

// Policy is the effective state of the derived settings.
type Policy struct {
	// Discovery and Reachability are the roles granted the permission.
	Discovery    []string
	Reachability []string
	// OriginIgnoreScheme and LegacySSHAlgorithms are the switches above.
	OriginIgnoreScheme  bool
	LegacySSHAlgorithms bool
}

// Granted reports whether role holds a permission of roles; an
// administrator always does.
func Granted(roles []string, role string, admin bool) bool {
	return admin || slices.Contains(roles, role)
}

func policyOf(rows map[string]appRow) Policy {
	roles := func(key string) []string {
		r, ok := rows[key]
		if !ok {
			return nil
		}
		members, _ := asObject(r.value)
		var out []string
		for _, m := range members {
			if v, ok := asBool(m.value); ok && v {
				out = append(out, m.name)
			}
		}
		slices.Sort(out)
		return out
	}
	flag := func(key string) bool {
		r, ok := rows[key]
		if !ok {
			return false
		}
		v, _ := asBool(r.value)
		return v
	}
	return Policy{
		Discovery:           roles(PolicyDiscovery),
		Reachability:        roles(PolicyReachability),
		OriginIgnoreScheme:  flag(PolicyOriginIgnoreScheme),
		LegacySSHAlgorithms: flag(PolicyLegacySSHAlgorithms),
	}
}

// Legacy describes the behaviour of the Python installation that the
// upgrade carries over. The migration fills it from the legacy data and
// configuration.
type Legacy struct {
	// KeepLegacyScheme is realtime.KeepLegacySchemeRule evaluated once
	// for the legacy configuration.
	KeepLegacyScheme bool
}

// Materialised is one derived setting as the migration report lists it
// (materialised_settings).
type Materialised struct {
	Setting  string `json:"setting"`
	Value    string `json:"value"`
	Rule     string `json:"rule"`
	Evidence string `json:"evidence"`
}

// MaterialisePolicies writes the derived settings of an existing
// installation in the migration transaction and returns them for the
// report. It is not called for a new installation.
//
// Discovery and the reachability check were open to every signed-in
// account, and paramiko offered the old SSH algorithms to every host, so
// those are always written. The origin rule is written only where the
// legacy configuration needed it.
func MaterialisePolicies(ctx context.Context, tx *store.Tx, l Legacy, nowUS int64) ([]Materialised, error) {
	items := []struct {
		key, rule, evidence string
		value               jsontext.Value
		display             string
		when                bool
	}{
		{PolicyDiscovery, "D-01/D-18/D-29", "every signed-in account could start host discovery",
			jsontext.Value(`{"user":true}`), "granted to role user", true},
		{PolicyReachability, "D-01/D-27", "every signed-in account could run the reachability check",
			jsontext.Value(`{"user":true}`), "granted to role user", true},
		{PolicyLegacySSHAlgorithms, "D-01/K2", "the Python release offered ssh-rsa, SHA-1 key exchange and CBC ciphers to every host",
			jsontext.Value("true"), "enabled for every host", true},
		{PolicyOriginIgnoreScheme, "D-01/K6-A1", "CORS_ORIGINS=* without trusted proxies compared only host and port",
			jsontext.Value("true"), "scheme not compared", l.KeepLegacyScheme},
	}
	var out []Materialised
	for _, it := range items {
		if !it.when {
			continue
		}
		if err := putApp(ctx, tx, it.key, it.value, SourceMaterialised, it.rule, nowUS); err != nil {
			return nil, err
		}
		out = append(out, Materialised{Setting: it.key, Value: it.display, Rule: it.rule, Evidence: it.evidence})
	}
	return out, nil
}

// MaterialisedSettings lists the stored derived settings, for the start
// warning and the administrator hint.
func (a App) MaterialisedSettings() []Materialised {
	var out []Materialised
	for _, key := range slices.Sorted(maps.Keys(a.rows)) {
		r := a.rows[key]
		if r.source == SourceMaterialised {
			out = append(out, Materialised{Setting: key, Value: string(r.value), Rule: r.rule})
		}
	}
	return out
}

// errPolicyKey refuses a legacy key that would shadow a derived setting.
func errPolicyKey(key string) error {
	return fmt.Errorf("%w: reserved key %s", ErrLegacyDocument, key)
}

package legacy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/settings"
	"github.com/bifrost0x/webssh/internal/store"
)

// appSettingsStep migrates entity E16, DATA_DIR/app_settings.json, into
// settings_app (settings.ImportApp). Python's start-up migrations
// (migrate_runtime_features, then migrate_feature_policies, app/__init__.py)
// are applied in memory first, with the environment of this start, so the
// stored values are those Python's next start would have used. Values
// and the opaque *_revision strings are copied verbatim.
type appSettingsStep struct {
	env settings.Environment

	doc       jsontext.Value
	present   bool
	generated []string // revisions generated as Python's start would
	imported  settings.AppImport
	flags     []string
	now       time.Time
}

func (*appSettingsStep) Entity() string { return "E16" }

func (*appSettingsStep) Version() int { return 1 }

func (s *appSettingsStep) Read(_ context.Context, src *Source) error {
	s.now = time.Now().UTC()
	members := []pyjson.Member{}
	doc, err := src.AppSettings()
	switch {
	case errors.Is(err, ErrNotFound):
	case err != nil:
		return &StepError{Record: "app_settings.json", Err: err}
	default:
		s.present = true
		members, _ = pyjson.Members(doc.Raw)
		if doc.LoneSurrogates {
			s.flags = append(s.flags, "lone_surrogate")
		}
		if doc.DuplicateNames {
			s.flags = append(s.flags, "duplicate_member_name")
		}
	}
	vaults, err := anyAutomationVault(src)
	if err != nil {
		return err
	}
	members = migrateRuntimeFeatures(members, s.env)
	members, s.generated = migrateFeaturePolicies(members, s.env, vaults)
	members = pyjson.Set(members, "schema_version", jsontext.Value("2"))
	s.doc = pyjson.Object(members)
	return nil
}

// anyAutomationVault is any(USERS_DIR.glob('*/automation-vault.json')).
func anyAutomationVault(src *Source) (bool, error) {
	dirs, err := src.UserDirectories()
	if err != nil {
		return false, err
	}
	for _, d := range dirs {
		if _, err := lstatChain(src.root, "users/"+d+"/automation-vault.json"); err == nil {
			return true, nil
		} else if !errors.Is(err, ErrNotFound) {
			return false, err
		}
	}
	return false, nil
}

// runtimeFeatures is RUNTIME_FEATURES of app/app_settings.py, in order.
var runtimeFeatures = [][2]string{
	{"sftp_chmod_enabled", "SFTP_CHMOD_ENABLED"}, {"server_operations_enabled", "SERVER_OPERATIONS_ENABLED"},
	{"tmux_enabled", "TMUX_ENABLED"}, {"tmux_default", "TMUX_DEFAULT"},
}

func boolJSON(b bool) jsontext.Value {
	if b {
		return jsontext.Value("true")
	}
	return jsontext.Value("false")
}

// isBool reports whether v is the JSON literal of b (Python's "is b").
func isBool(v jsontext.Value, b bool) bool { return string(v) == string(boolJSON(b)) }

func memberValue(members []pyjson.Member, name string) (jsontext.Value, bool) {
	i := slices.IndexFunc(members, func(m pyjson.Member) bool { return m.Name == name })
	if i < 0 {
		return nil, false
	}
	return members[i].Value, true
}

// migrateRuntimeFeatures is app_settings.migrate_runtime_features.
func migrateRuntimeFeatures(members []pyjson.Member, env settings.Environment) []pyjson.Member {
	var migrated []jsontext.Value
	if v, ok := memberValue(members, "runtime_feature_migration"); ok {
		migrated, _ = pyjson.Items(v)
	}
	changed := false
	for _, f := range runtimeFeatures {
		name, key := f[0], f[1]
		if !env.Explicit[key] {
			continue
		}
		value := env.Values[key]
		current, present := memberValue(members, name)
		switch {
		case !present:
			members = pyjson.Set(members, name, boolJSON(value))
			migrated = append(migrated, pyjson.String(name))
			changed = true
		case slices.ContainsFunc(migrated, func(v jsontext.Value) bool { return string(v) == string(pyjson.String(name)) }) && !isBool(current, value):
			members = pyjson.Set(members, name, boolJSON(value))
			changed = true
		}
	}
	if changed {
		members = pyjson.Set(members, "runtime_feature_migration", pyjson.Array(migrated))
	}
	return members
}

// migrateFeaturePolicies is app_settings.migrate_feature_policies with
// automation_enabled=AUTOMATION_ENABLED and credentials_enabled=any
// automation vault. It returns the names of the revisions it generated.
func migrateFeaturePolicies(members []pyjson.Member, env settings.Environment, vaults bool) ([]pyjson.Member, []string) {
	var generated []string
	explicit := env.Explicit["AUTOMATION_ENABLED"]
	automation := env.Values["AUTOMATION_ENABLED"]
	for _, p := range []struct {
		name  string
		value bool
	}{{"credentials_enabled", vaults}, {"automation_enabled", automation}} {
		if _, ok := memberValue(members, p.name); ok {
			continue
		}
		members = pyjson.Set(members, p.name, boolJSON(p.value))
		members = pyjson.Set(members, p.name+"_revision", pyjson.String(newRevision()))
		generated = append(generated, p.name+"_revision")
		if p.name == "automation_enabled" && explicit {
			members = pyjson.Set(members, "automation_enabled_from_environment", boolJSON(true))
		}
	}
	if v, _ := memberValue(members, "automation_enabled_from_environment"); isBool(v, true) && explicit {
		if current, _ := memberValue(members, "automation_enabled"); !isBool(current, automation) {
			members = pyjson.Set(members, "automation_enabled", boolJSON(automation))
		}
	}
	effective := automation
	if !explicit {
		v, _ := memberValue(members, "automation_enabled")
		effective = isBool(v, true)
	}
	if observed, _ := memberValue(members, "automation_effective_observed"); !isBool(observed, effective) {
		if isBool(observed, true) || isBool(observed, false) {
			members = pyjson.Set(members, "automation_enabled_revision", pyjson.String(newRevision()))
			generated = append(generated, "automation_enabled_revision")
		}
		members = pyjson.Set(members, "automation_effective_observed", boolJSON(effective))
	}
	return members, generated
}

// newRevision is secrets.token_hex(32).
func newRevision() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never fails
	return hex.EncodeToString(b)
}

func (s *appSettingsStep) Write(ctx context.Context, tx *store.Tx, _ Sealer) error {
	var err error
	s.imported, err = settings.ImportApp(ctx, tx, s.doc, s.now.UnixMicro())
	if err != nil {
		return &StepError{Record: "app_settings.json", Err: err}
	}
	return nil
}

func (s *appSettingsStep) Verify(ctx context.Context, tx *store.Tx, _ Opener) error {
	if err := settings.VerifyApp(ctx, tx, s.doc); err != nil {
		return &StepError{Record: "app_settings.json", Err: err}
	}
	return nil
}

func (s *appSettingsStep) Report() StepReport {
	r := StepReport{Entity: "E16", Version: 1, Written: len(s.imported.Keys)}
	if s.present {
		r.Read = 1
	}
	if len(s.generated) > 0 {
		r.Notes = append(r.Notes, "generated as the Python release's next start would: "+strings.Join(s.generated, ", "))
	}
	if len(s.imported.Skipped) > 0 {
		r.Notes = append(r.Notes, "kept only in the legacy file: "+strings.Join(s.imported.Skipped, ", "))
	}
	for _, f := range s.flags {
		r.Flagged = append(r.Flagged, Flag{ID: "app_settings.json", Reason: f})
	}
	return r
}

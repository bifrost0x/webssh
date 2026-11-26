package settings

import (
	"context"
	"encoding/json/jsontext"

	"github.com/bifrost0x/webssh/internal/fault"
)

// TourDeployment are the deployment facts the introduction tour shows,
// filled by the composition root. Values holds the effective boolean of
// every variable in tourEnvironmentFacts; a capability the running build
// does not offer is reported false.
type TourDeployment struct {
	Values            map[string]bool
	AdminPanelEnabled bool
	// ProcessRoot says whether the process runs as root; nil where the
	// platform has no such notion.
	ProcessRoot *bool
}

// tourEnvironmentFacts are the allowlisted environment facts, in the order
// of the Python release. Environment variables, configuration and paths
// are never serialized beyond these booleans.
var tourEnvironmentFacts = []string{
	"SMB_ENABLED", "SFTP_CHMOD_ENABLED", "SERVER_OPERATIONS_ENABLED",
	"TMUX_ENABLED", "TAILSCALE_SSH_ENABLED", "OIDC_ENABLED",
	"LDAP_ENABLED", "TOTP_ENABLED", "WEBAUTHN_ENABLED",
	"BOOTSTRAP_REGISTRATION_ENABLED", "SESSION_COOKIE_SECURE",
}

// tourAdminOnlyFacts describe the deployment posture; other accounts do
// not see them.
var tourAdminOnlyFacts = []string{"SESSION_COOKIE_SECURE", "BOOTSTRAP_REGISTRATION_ENABLED"}

// tourRuntimeFacts are the runtime switches that replace their
// environment fact (tmux_default has none).
var tourRuntimeFacts = map[string]string{
	"SFTP_CHMOD_ENABLED":        "sftp_chmod_enabled",
	"SERVER_OPERATIONS_ENABLED": "server_operations_enabled",
	"TMUX_ENABLED":              "tmux_enabled",
}

// tourGatedFacts are the security features whose fact is the gate state.
var tourGatedFacts = map[string]string{
	"OIDC_ENABLED": "oidc", "LDAP_ENABLED": "ldap", "TOTP_ENABLED": "totp", "WEBAUTHN_ENABLED": "passkey",
}

type tourFact struct {
	Key        string `json:"key"`
	Enabled    bool   `json:"enabled"`
	Source     string `json:"source,omitzero"`
	Configured *bool  `json:"configured,omitzero"`
}

type tourResponse struct {
	State         string     `json:"state"`
	Administrator bool       `json:"administrator"`
	AdminURL      *string    `json:"admin_url"`
	ProcessRoot   *bool      `json:"process_root"`
	Facts         []tourFact `json:"facts"`
}

// tourState is "completed" once the current tour was acknowledged,
// "dismissed" when it was skipped (never reopened on every page load) and
// "new" otherwise.
func tourState(u User) string {
	switch {
	case u.TourAcknowledged:
		return "completed"
	case u.Tour == "dismissed":
		return "dismissed"
	}
	return "new"
}

func (h *HTTP) tourFacts(ctx context.Context, app App) ([]tourFact, error) {
	facts := make([]tourFact, 0, len(tourEnvironmentFacts)+3)
	for _, key := range tourEnvironmentFacts {
		f := tourFact{Key: key, Enabled: h.Tour.Values[key], Source: "environment"}
		if name, ok := tourRuntimeFacts[key]; ok {
			st := app.RuntimeFeature(name)
			f.Enabled, f.Source = st.Enabled, st.Source
		}
		if feature, ok := tourGatedFacts[key]; ok {
			configured := f.Enabled
			active := false
			if h.Gates != nil {
				var err error
				if active, err = h.Gates.FeatureActive(ctx, feature); err != nil {
					return nil, err
				}
			}
			f.Configured, f.Enabled, f.Source = &configured, active, "deployment_and_admin"
		}
		facts = append(facts, f)
	}
	return append(facts,
		tourFact{Key: "credentials_enabled", Enabled: app.CredentialsEnabled, Source: "admin"},
		tourFact{Key: "automation_enabled", Enabled: app.AutomationEnabled, Source: "admin"},
		tourFact{Key: "registration_enabled", Enabled: app.RegistrationEnabled, Source: "admin"},
	), nil
}

// tourRequest checks {state, acknowledged}: completing the tour needs an
// explicit acknowledgement.
func tourRequest(body map[string]jsontext.Value) (string, error) {
	for name := range body {
		if name != "state" && name != "acknowledged" {
			return "", fault.New(fault.InvalidRequest, msgInvalidTourState)
		}
	}
	v, ok := body["state"]
	if !ok {
		return "", fault.New(fault.InvalidRequest, msgInvalidTourState)
	}
	state, ok := asString(v)
	if !ok || !in(TourStates, state) {
		return "", fault.New(fault.InvalidRequest, msgInvalidTourState)
	}
	if state == "completed" && string(body["acknowledged"]) != "true" {
		return "", fault.New(fault.InvalidRequest, msgAcknowledgeMissing)
	}
	return state, nil
}

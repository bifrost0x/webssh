package operations

import (
	"context"
	"encoding/json/jsontext"
	"regexp"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Support report (C-SUP-01): an allowlisted snapshot the signed-in user
// copies into a support request. It never connects to a target, reads
// logs or lists account data; the shape is that of support_report.py.

// SupportAreas are the areas a report can be made for.
var SupportAreas = []string{"general", "ssh", "files", "sign_in", "automation"}

// supportReference is the optional reference of an SMB diagnosis.
var supportReference = regexp.MustCompile(`\ASMB-[A-F0-9]{12}\z`)

// SupportRequest is the body of POST /api/account/support-report.
type SupportRequest struct {
	Area      string `json:"area"`
	Reference string `json:"reference"`
}

// Validate applies the defaults and refuses anything else with
// fault.InvalidRequest ("Invalid report options"), as the Python release
// does; unknown members are refused by the strict decoder before.
func (r *SupportRequest) Validate() error {
	if r.Area == "" {
		r.Area = "general"
	}
	if !slices.Contains(SupportAreas, r.Area) || r.Reference != "" && !supportReference.MatchString(r.Reference) {
		return fault.New(fault.InvalidRequest, "Invalid report options")
	}
	return nil
}

// SupportFeatures are the feature flags of a report, in this order.
var SupportFeatures = []string{"ssh", "sftp", "smb", "tmux", "automation", "saved_passwords",
	"passkey", "totp", "oidc", "ldap", "recovery"}

// SupportReadinessFailures are the readiness checks a report may name.
var SupportReadinessFailures = []string{"maintenance", "runtime", "database", "data_directory"}

// SupportDeployment is the part of a report only administrators get.
type SupportDeployment struct {
	Profile            string `json:"profile"` // homelab, production or unknown
	SecureCookie       bool   `json:"secure_cookie"`
	InternalSSHBlocked bool   `json:"internal_ssh_blocked"`
}

// SupportFacts are the local facts a report reads (provided by the
// composition root): never a remote target, a log or account data.
type SupportFacts interface {
	Version() string
	// ReadinessFailures are the failed checks of /ready, none when ready.
	ReadinessFailures(ctx context.Context) []string
	// Features reports the features of SupportFeatures; a missing one is off.
	Features(ctx context.Context) map[string]bool
	Deployment() SupportDeployment
}

// SupportReadiness is the readiness part of a report.
type SupportReadiness struct {
	Status string   `json:"status"`
	Failed []string `json:"failed"`
}

// SupportReport is the report, with the members in the order the Python
// release sends them (sorted by name).
type SupportReport struct {
	Area        string             `json:"area"`
	Deployment  *SupportDeployment `json:"deployment,omitzero"`
	Features    supportFeatures    `json:"features"`
	GeneratedAt string             `json:"generated_at"`
	HTTPS       bool               `json:"https"`
	Readiness   SupportReadiness   `json:"readiness"`
	Reference   *string            `json:"reference"`
	Schema      int                `json:"schema"`
	Version     string             `json:"version"`
}

// supportFeatures marshals the flags in the sorted order of the Python
// answer.
type supportFeatures map[string]bool

func (f supportFeatures) MarshalJSONTo(enc *jsontext.Encoder) error {
	if err := enc.WriteToken(jsontext.BeginObject); err != nil {
		return err
	}
	for _, name := range slices.Sorted(slices.Values(SupportFeatures)) {
		if err := enc.WriteToken(jsontext.String(name)); err != nil {
			return err
		}
		if err := enc.WriteToken(jsontext.Bool(f[name])); err != nil {
			return err
		}
	}
	return enc.WriteToken(jsontext.EndObject)
}

// BuildSupportReport assembles the report for a validated request.
func BuildSupportReport(ctx context.Context, facts SupportFacts, req SupportRequest, admin, https bool, now time.Time) SupportReport {
	failed := facts.ReadinessFailures(ctx)
	r := SupportReport{
		Schema: 1, GeneratedAt: pyISO(now),
		Version: facts.Version(), Area: req.Area, HTTPS: https,
		Readiness: SupportReadiness{Status: "ready", Failed: []string{}},
		Features:  supportFeatures{},
	}
	if req.Reference != "" {
		ref := req.Reference
		r.Reference = &ref
	}
	if len(failed) > 0 {
		r.Readiness.Status = "not_ready"
	}
	for _, name := range SupportReadinessFailures {
		if slices.Contains(failed, name) {
			r.Readiness.Failed = append(r.Readiness.Failed, name)
		}
	}
	got := facts.Features(ctx)
	for _, name := range SupportFeatures {
		r.Features[name] = got[name]
	}
	r.Features["ssh"], r.Features["sftp"] = true, true
	if admin {
		d := facts.Deployment()
		if d.Profile != "homelab" && d.Profile != "production" {
			d.Profile = "unknown"
		}
		r.Deployment = &d
	}
	return r
}

// pyISO is datetime.now(timezone.utc).isoformat(): microseconds only
// when they are not zero.
func pyISO(t time.Time) string {
	t = t.UTC()
	if t.Nanosecond()/1000 == 0 {
		return t.Format("2006-01-02T15:04:05") + "+00:00"
	}
	return t.Format("2006-01-02T15:04:05.000000") + "+00:00"
}

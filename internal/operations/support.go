package operations

import (
	"regexp"
	"slices"

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

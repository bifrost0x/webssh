package protocol

import "encoding/json/jsontext"

// Message types of the areas "insights", "inventory" and "herdr" (HO1):
// one bounded sample of a connected session, read on a separate channel of
// its connection (docs/architecture/m2-contracts.md, "Message types
// (insights, inventory, herdr)"). Failures are answers with success false
// and a reason, as the Socket.IO events of the Python release carried
// them; the request never fails for a missing or foreign session.
const (
	TypeInsightsSample  = "insights.sample"
	TypeInventorySample = "inventory.sample"
	TypeHerdrSnapshot   = "herdr.snapshot"
)

// SessionSampleMaxPayload bounds the requests of the three types.
const SessionSampleMaxPayload = 1 << 10

// InsightsSample asks for one Linux sample of a session
// (request_session_insights). Identifiers of 1 to 128 bytes; anything
// else is answered with success false and empty identifiers.
type InsightsSample struct {
	SessionID          string `json:"session_id"`
	RequestID          string `json:"request_id"`
	IncludeDiagnostics bool   `json:"include_diagnostics,omitzero"`
}

// InsightsResult is the session_insights event. Stats is the parsed
// sample; Reason is one of busy, transient, unsupported and
// resource_shortage, or empty.
type InsightsResult struct {
	Success   bool           `json:"success"`
	SessionID string         `json:"session_id"`
	RequestID string         `json:"request_id"`
	Stats     jsontext.Value `json:"stats,omitzero"`
	Error     string         `json:"error,omitzero"`
	Reason    string         `json:"reason,omitzero"`
}

// InventorySample asks for the runtime inventory of a session
// (request_session_runtime_inventory).
type InventorySample struct {
	SessionID string `json:"session_id"`
	RequestID string `json:"request_id"`
}

// InventoryResult is the session_runtime_inventory event: the sections
// systemd and docker when they were complete, and the scopes the account
// may not read.
type InventoryResult struct {
	Success          bool           `json:"success"`
	SessionID        string         `json:"session_id"`
	RequestID        string         `json:"request_id"`
	SampledAt        int64          `json:"sampled_at,omitzero"`
	Systemd          jsontext.Value `json:"systemd,omitzero"`
	Docker           jsontext.Value `json:"docker,omitzero"`
	PermissionDenied []string       `json:"permission_denied,omitzero"`
	Error            string         `json:"error,omitzero"`
}

// HerdrSnapshot asks for the Herdr agents of a session
// (request_herdr_snapshot).
type HerdrSnapshot struct {
	SessionID string `json:"session_id"`
}

// HerdrResult is the acknowledgement of request_herdr_snapshot. Reason
// names why there are no agents (disabled, not_enabled, busy, timeout,
// not_installed, no_server, incompatible, invalid, unavailable,
// disconnected) or is null.
type HerdrResult struct {
	Success   bool         `json:"success"`
	Agents    []HerdrAgent `json:"agents"`
	Truncated bool         `json:"truncated"`
	Reason    *string      `json:"reason"`
}

// HerdrAgent is one agent Herdr reports; every text is remote-supplied,
// bounded and cleaned, and shown as text only.
type HerdrAgent struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Label  string `json:"label"`
	CWD    string `json:"cwd"`
	Status string `json:"status"`
}

package protocol

import "errors"

// Prompt contexts: which hop of the connection asks.
const (
	PromptTarget   = "target"
	PromptJumpHost = "jump_host"
)

// Prompt kinds of prompt.answer.
const (
	PromptKindHostKey = "host_key"
	PromptKindBanner  = "banner"
)

// PromptHostKey asks the user to trust a host key seen for the first time.
// It is bound to the connection, the user and RequestID; it expires after
// 60 seconds and is then closed with prompt.closed.
type PromptHostKey struct {
	PromptID    string `json:"prompt_id"`
	RequestID   string `json:"request_id"`
	Context     string `json:"context"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	KeyType     string `json:"key_type"`
	Fingerprint string `json:"fingerprint"`
}

// PromptBanner asks the user to accept a pre-authentication banner.
type PromptBanner struct {
	PromptID  string `json:"prompt_id"`
	RequestID string `json:"request_id"`
	Context   string `json:"context"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Banner    string `json:"banner"`
}

// PromptClosed withdraws a prompt (answered elsewhere, expired, cancelled).
type PromptClosed struct {
	PromptID  string `json:"prompt_id"`
	RequestID string `json:"request_id"`
}

// PromptAnswer is the user's decision.
type PromptAnswer struct {
	PromptID string `json:"prompt_id"`
	Kind     string `json:"kind"`
	Accepted bool   `json:"accepted"`
}

// Validate implements Validator.
func (r *PromptAnswer) Validate() error {
	if r.Kind != PromptKindHostKey && r.Kind != PromptKindBanner {
		return errors.New("kind must be host_key or banner")
	}
	if !validToken(r.PromptID, MaxIDLen, false) {
		return errors.New("prompt_id is invalid")
	}
	return nil
}

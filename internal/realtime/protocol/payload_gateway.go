package protocol

import (
	"errors"
	"unicode/utf8"
)

// Message types of the area "gateway" (NW2): the keyboard-interactive
// prompts of a connection attempt and the temporary terminal in which an
// SSH gateway such as Warpgate asks its own questions before the target is
// reached (docs/architecture/m2-contracts.md, "Message types (gateway)").
const (
	TypePromptInteractive = "prompt.interactive"
	TypePromptRespond     = "prompt.respond"
	TypeGatewaySetup      = "gateway.setup"
	TypeGatewayOutput     = "gateway.output"
	TypeGatewayInput      = "gateway.input"
	TypeGatewayAck        = "gateway.ack"
)

// Limits of an interactive attempt. They are those of the Python release
// (app/ssh_gateway_interaction.py).
const (
	MaxInteractivePrompts = 8
	// MaxInteractiveBytes bounds the UTF-8 bytes of a challenge (title,
	// instructions and labels) and, separately, of the answers to it.
	MaxInteractiveBytes = 16 << 10
	// MaxGatewayInput bounds one gateway.input in UTF-8 bytes.
	MaxGatewayInput = 1024
)

// Payload bounds of the client requests of the area. A JSON string may
// escape every byte as \u00XX, so the bounds leave room for six bytes per
// payload byte.
const (
	PromptRespondMaxPayload = 6*MaxInteractiveBytes + 1024
	GatewayInputMaxPayload  = 6*MaxGatewayInput + 512
)

// PromptInteractive is one keyboard-interactive round the server asks the
// user to answer, for the SSH gateway or a jump host in front of it.
// ExpiresIn is the time left to answer in seconds; afterwards the attempt
// ends. The texts are remote-supplied, valid UTF-8 and shown as text only.
type PromptInteractive struct {
	PromptID     string              `json:"prompt_id"`
	RequestID    string              `json:"request_id"`
	Context      string              `json:"context"`
	Title        string              `json:"title"`
	Instructions string              `json:"instructions"`
	Prompts      []InteractivePrompt `json:"prompts"`
	ExpiresIn    int                 `json:"expires_in"`
}

// InteractivePrompt is one question of a round. Echo is the server's
// echo flag; the page may still mask every answer.
type InteractivePrompt struct {
	Label string `json:"label"`
	Echo  bool   `json:"echo"`
}

// PromptRespond answers the pending prompt of the attempt RequestID, one
// string per prompt.
type PromptRespond struct {
	RequestID string   `json:"request_id"`
	PromptID  string   `json:"prompt_id"`
	Answers   []string `json:"answers"`
}

// Validate implements Validator.
func (r *PromptRespond) Validate() error {
	if !validToken(r.RequestID, MaxIDLen, false) {
		return errors.New("request_id is invalid")
	}
	if !validToken(r.PromptID, MaxIDLen, false) {
		return errors.New("prompt_id is invalid")
	}
	if len(r.Answers) > MaxInteractivePrompts {
		return errors.New("too many answers")
	}
	total := 0
	for _, a := range r.Answers {
		if !utf8.ValidString(a) {
			return errors.New("answers must be text")
		}
		total += len(a)
	}
	if total > MaxInteractiveBytes {
		return errors.New("answers are too large")
	}
	return nil
}

// GatewaySetup announces that authentication is done and the gateway's
// temporary terminal is open. Phase is "setup".
type GatewaySetup struct {
	RequestID string `json:"request_id"`
	Phase     string `json:"phase"`
}

// GatewayOutput is one frame of the temporary terminal, at most 4 KiB of
// output as text. The page acknowledges each Sequence with gateway.ack.
type GatewayOutput struct {
	RequestID string `json:"request_id"`
	Sequence  uint64 `json:"sequence"`
	Data      string `json:"data"`
}

// GatewayInput is what the user typed into the temporary terminal.
type GatewayInput struct {
	RequestID string `json:"request_id"`
	Data      string `json:"data"`
}

// Validate implements Validator.
func (r *GatewayInput) Validate() error {
	if !validToken(r.RequestID, MaxIDLen, false) {
		return errors.New("request_id is invalid")
	}
	if r.Data == "" || len(r.Data) > MaxGatewayInput || !utf8.ValidString(r.Data) {
		return errors.New("data is invalid")
	}
	return nil
}

// GatewayAck acknowledges one gateway.output frame.
type GatewayAck struct {
	RequestID string `json:"request_id"`
	Sequence  uint64 `json:"sequence"`
}

// Validate implements Validator.
func (r *GatewayAck) Validate() error {
	if !validToken(r.RequestID, MaxIDLen, false) {
		return errors.New("request_id is invalid")
	}
	return nil
}

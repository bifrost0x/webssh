// Package protocol defines the versioned wire contract between the browser
// and the realtime endpoint (ADR 0005): the JSON envelope of control
// messages, the binary frame layout of terminal data, the close codes and
// the catalog of message types of schema v1.
//
// The package imports only the standard library and foundation packages,
// so capability packages declare their handlers against it without
// importing the WebSocket edge (internal/realtime).
//
// Decoding is strict on purpose (condition K6): an envelope or payload with
// unknown, duplicate or differently cased member names, trailing data or
// invalid UTF-8 is rejected, so that the browser and the server can never
// disagree about what a message says.
package protocol

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version is the schema version this build speaks. A client announces the
// versions it supports as WebSocket subprotocols ("webssh.v1", ...); the
// server picks the highest common one or closes with CloseUnsupportedVersion.
const Version = 1

// SubprotocolPrefix is followed by the decimal schema version.
const SubprotocolPrefix = "webssh.v"

// Subprotocol returns the subprotocol token for a schema version.
func Subprotocol(version int) string {
	return SubprotocolPrefix + strconv.Itoa(version)
}

// ParseSubprotocol returns the schema version of a subprotocol token.
func ParseSubprotocol(token string) (int, bool) {
	rest, ok := strings.CutPrefix(token, SubprotocolPrefix)
	if !ok || rest == "" || len(rest) > 4 || rest[0] == '0' {
		return 0, false
	}
	v, err := strconv.Atoi(rest)
	if err != nil || v <= 0 {
		return 0, false
	}
	return v, true
}

// Close codes in the private range 4000-4999 (RFC 6455, section 7.4.2).
// Browsers expose code and reason to the page, so every refusal after the
// upgrade carries one of these instead of a bare disconnect.
const (
	CloseUnsupportedVersion = 4001 // no common schema version: reload the page
	CloseProtocolViolation  = 4002 // malformed frame or envelope
	CloseUnauthenticated    = 4003 // session ended, revoked or never valid
	CloseSlowConsumer       = 4008 // the client did not keep up (queue overflow, write timeout)
	CloseMaintenance        = 4503 // server enters maintenance or shuts down
)

// Envelope is the single JSON shape of every text frame in both directions.
//
//	{"v":1,"t":"terminal.open","id":"c17","p":{...}}
//
// T names the message type ("<capability>.<verb>"). ID is set by the
// client on requests that expect a result and echoed in the matching
// "result" message; requests without ID are fire-and-forget. Server events
// never carry an ID. P, when present, is a JSON object.
type Envelope struct {
	V  int            `json:"v"`
	T  string         `json:"t"`
	ID string         `json:"id,omitzero"`
	P  jsontext.Value `json:"p,omitzero"`
}

// Limits of the envelope itself, independent of the message type.
const (
	MaxTypeLen = 64
	MaxIDLen   = 128
)

// ErrEnvelope marks a text frame that is not a valid envelope. The edge
// closes the connection with CloseProtocolViolation on it.
var ErrEnvelope = errors.New("protocol: invalid envelope")

// strict are the decoding options for everything a client sends. Member
// names are matched case-sensitively and duplicate names and invalid
// UTF-8 are rejected by default in encoding/json/v2; unknown members are
// rejected here.
var strict = []json.Options{json.RejectUnknownMembers(true)}

// DecodeEnvelope parses a text frame strictly.
func DecodeEnvelope(data []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(data, &env, strict...); err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrEnvelope, err)
	}
	if env.V != Version {
		return Envelope{}, fmt.Errorf("%w: version %d", ErrEnvelope, env.V)
	}
	if !validToken(env.T, MaxTypeLen, true) {
		return Envelope{}, fmt.Errorf("%w: type", ErrEnvelope)
	}
	if env.ID != "" && !validToken(env.ID, MaxIDLen, false) {
		return Envelope{}, fmt.Errorf("%w: id", ErrEnvelope)
	}
	if len(env.P) > 0 && env.P.Kind() != '{' {
		return Envelope{}, fmt.Errorf("%w: payload is not an object", ErrEnvelope)
	}
	return env, nil
}

// validToken accepts [a-z0-9._-] for types and [A-Za-z0-9:._-] for ids.
func validToken(s string, maxLen int, isType bool) bool {
	if s == "" || len(s) > maxLen {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		case !isType && (c >= 'A' && c <= 'Z' || c == ':'):
		default:
			return false
		}
	}
	return true
}

// ValidType reports whether s is a well-formed message type name.
func ValidType(s string) bool { return validToken(s, MaxTypeLen, true) }

// EncodeEnvelope marshals a message with the current version. A non-nil
// payload must encode to a JSON object.
func EncodeEnvelope(typ, id string, payload any) ([]byte, error) {
	env := Envelope{V: Version, T: typ, ID: id}
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("protocol: encode %s: %w", typ, err)
		}
		if v := jsontext.Value(raw); v.Kind() != '{' {
			return nil, fmt.Errorf("protocol: encode %s: payload is not an object", typ)
		}
		env.P = raw
	}
	return json.Marshal(env)
}

// DecodePayload decodes p strictly into v; an empty payload decodes as {}.
func DecodePayload(p jsontext.Value, v any) error {
	if len(p) == 0 {
		p = jsontext.Value("{}")
	}
	if err := json.Unmarshal(p, v, strict...); err != nil {
		return fmt.Errorf("protocol: payload: %w", err)
	}
	return nil
}

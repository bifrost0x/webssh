package automation

import (
	"errors"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Error is an AutomationError of the Python release: a code the page
// knows. Hosts names the user's own saved hosts whose host key still
// needs a verification (host_key_required).
type Error struct {
	Code  string
	Hosts []string
}

func (e *Error) Error() string { return "automation: " + e.Code }

// Fail returns the error with the given code.
func Fail(code string) error { return &Error{Code: code} }

// NotDispatched reports that a run was definitely not started: nothing
// reached any target (AutomationNotDispatched).
type NotDispatched struct{ Code string }

func (e *NotDispatched) Error() string { return "automation: not dispatched: " + e.Code }

// Code returns the code of an automation error, "" for any other error.
func Code(err error) string {
	if e, ok := errors.AsType[*Error](err); ok {
		return e.Code
	}
	if e, ok := errors.AsType[*NotDispatched](err); ok {
		return e.Code
	}
	return ""
}

func notDispatched(err error) error {
	if _, ok := errors.AsType[*NotDispatched](err); ok {
		return err
	}
	if c := Code(err); c != "" {
		return &NotDispatched{Code: c}
	}
	return &NotDispatched{Code: "unavailable"}
}

// status is the status map of automation_routes.py failure(); every
// other code answers 400.
var status = map[string]int{
	"authentication_required":        401,
	string(fault.AutomationDisabled): 403,
	"https_required":                 403,
	"step_up_required":               403,
	"busy":                           429,
	"not_found":                      404,
	"invalid_intent":                 409,
	"preview_changed":                409,
	"vault_locked":                   423,
	"unavailable":                    503,
	"credentials_disabled":           403,
	"host_key_required":              409,
	"run_active":                     409,
	// The storage handlers of the blueprint.
	"storage_unavailable": 409,
}

// HTTPStatus returns the status of an automation code.
func HTTPStatus(code string) int {
	if s, ok := status[code]; ok {
		return s
	}
	return 400
}

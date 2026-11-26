package fault

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestStatus(t *testing.T) {
	t.Parallel()
	secret := errors.New("open /data/webssh.db: password=hunter2")
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   Code
		wantMsg    string
	}{
		{name: "nil", err: nil, wantStatus: 200},
		{name: "default message", err: New(NotFound, ""), wantStatus: 404, wantCode: NotFound, wantMsg: "Not found."},
		{name: "own message", err: New(Conflict, "Jump host is in use."), wantStatus: 409, wantCode: Conflict, wantMsg: "Jump host is in use."},
		{name: "wrapped twice", err: fmt.Errorf("save: %w", Wrap(StorageError, secret, "")), wantStatus: 500, wantCode: StorageError, wantMsg: "The data could not be stored."},
		{name: "unclassified hides text", err: secret, wantStatus: 500, wantCode: Internal, wantMsg: "An internal error occurred."},
		{name: "unknown code hides message", err: New(Code("made_up"), "internal detail"), wantStatus: 500, wantCode: Internal, wantMsg: "An internal error occurred."},
		{name: "preview", err: New(NotAvailableInPreview, ""), wantStatus: 501, wantCode: NotAvailableInPreview, wantMsg: "Not available in this preview yet."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status, code, msg := Status(tt.err)
			if status != tt.wantStatus || code != tt.wantCode || msg != tt.wantMsg {
				t.Fatalf("Status() = %d, %q, %q; want %d, %q, %q", status, code, msg, tt.wantStatus, tt.wantCode, tt.wantMsg)
			}
			if strings.Contains(msg, "hunter2") {
				t.Fatal("cause leaked into the safe message")
			}
		})
	}
}

func TestErrorChain(t *testing.T) {
	t.Parallel()
	cause := errors.New("disk full")
	err := fmt.Errorf("write profile: %w", Wrap(StorageError, cause, ""))
	if !errors.Is(err, cause) {
		t.Error("cause not reachable with errors.Is")
	}
	if !errors.Is(err, New(StorageError, "other text")) {
		t.Error("errors.Is does not match by code")
	}
	if errors.Is(err, New(NotFound, "")) {
		t.Error("errors.Is matched a different code")
	}
	if !Is(err, StorageError) || Is(nil, StorageError) || CodeOf(nil) != "" {
		t.Error("Is or CodeOf wrong")
	}
	if got := err.Error(); !strings.Contains(got, "disk full") || !strings.Contains(got, "storage_error") {
		t.Errorf("log text %q lacks code or cause", got)
	}
	limited := &Error{Code: RateLimited, RetryAfter: 3 * time.Second}
	if RetryAfter(fmt.Errorf("x: %w", limited)) != 3*time.Second || RetryAfter(cause) != 0 {
		t.Error("RetryAfter wrong")
	}
}

func TestCatalog(t *testing.T) {
	t.Parallel()
	valid := regexp.MustCompile(`^[a-z][a-z0-9_]*[a-z0-9]$`)
	// The file and transfer codes keep the upper-case spelling of the
	// Python release (codes_data.go); no other code may use it.
	upper := regexp.MustCompile(`^[A-Z][A-Z0-9_]*[A-Z0-9]$`)
	for _, c := range Codes() {
		_, data := dataCatalog[c]
		ok := valid.MatchString(string(c)) || data && upper.MatchString(string(c))
		if !ok || len(c) > 64 {
			t.Errorf("code %q is not snake case up to 64 bytes", c)
		}
		if s := c.HTTPStatus(); s < 400 || s > 599 {
			t.Errorf("code %q maps to status %d", c, s)
		}
		msg := c.DefaultMessage()
		if msg == "" || !strings.HasSuffix(msg, ".") {
			t.Errorf("code %q: default message %q must be a full sentence", c, msg)
		}
	}
	if Code("made_up").Known() || Code("made_up").HTTPStatus() != 500 {
		t.Error("unknown code treated as known")
	}
}

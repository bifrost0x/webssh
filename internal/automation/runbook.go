package automation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// Limits of the runbook library (automation_store.py).
const (
	MaxRunbooks     = 100
	MaxSteps        = 20
	MaxStepCommand  = 8192
	MaxNameBytes    = 128
	MaxIDBytes      = 64
	DefaultTimeout  = 30
	MaxTimeout      = 300
	MaxStoreBytes   = 1 << 20
	storeVersion    = 1
	defaultStopFlag = true
)

// Runbook is a saved workflow: ordered steps, each a shell script.
type Runbook struct {
	ID          string
	Name        string
	Steps       []Step
	StopOnError bool
}

// Step is one step of a runbook.
type Step struct {
	Name    string
	Command string
	Timeout int // seconds, 1 to MaxTimeout
	Sudo    bool
}

// Value is the runbook as the page and the digest see it, in the member
// order of normalize_runbook.
func (b Runbook) Value() jsontext.Value {
	steps := make([]jsontext.Value, len(b.Steps))
	for i, s := range b.Steps {
		steps[i] = pyjson.Object([]pyjson.Member{
			{Name: "name", Value: pyjson.String(s.Name)},
			{Name: "command", Value: pyjson.String(s.Command)},
			{Name: "timeout", Value: jsontext.Value(strconv.Itoa(s.Timeout))},
			{Name: "sudo", Value: jsonBool(s.Sudo)},
		})
	}
	return pyjson.Object([]pyjson.Member{
		{Name: "id", Value: pyjson.String(b.ID)},
		{Name: "name", Value: pyjson.String(b.Name)},
		{Name: "steps", Value: pyjson.Array(steps)},
		{Name: "stop_on_error", Value: jsonBool(b.StopOnError)},
	})
}

// Digest is digest() of the runbook: SHA-256 of its sorted, compact
// JSON with ASCII escapes. Schedules bind their grant to it.
func (b Runbook) Digest() string {
	sum := sha256.Sum256([]byte(pyDump(b.Value(), dumpOptions{sortKeys: true})))
	return hex.EncodeToString(sum[:])
}

func (b Runbook) equal(o Runbook) bool {
	if b.ID != o.ID || b.Name != o.Name || b.StopOnError != o.StopOnError || len(b.Steps) != len(o.Steps) {
		return false
	}
	for i := range b.Steps {
		if b.Steps[i] != o.Steps[i] {
			return false
		}
	}
	return true
}

func jsonBool(v bool) jsontext.Value {
	if v {
		return jsontext.Value("true")
	}
	return jsontext.Value("false")
}

// NormalizeRunbook is normalize_runbook: the request value checked in the
// order of the Python release, so the same input fails with the same
// code. A value without an id gets a new one.
func NormalizeRunbook(v jsontext.Value) (Runbook, error) {
	if v.Kind() != '{' {
		return Runbook{}, Fail("invalid_runbook")
	}
	stepsV, ok := pyjson.Get(v, "steps")
	items, isList := pyjson.Items(stepsV)
	if !ok || !isList || len(items) < 1 || len(items) > MaxSteps {
		return Runbook{}, Fail("invalid_runbook")
	}
	var b Runbook
	for _, item := range items {
		if item.Kind() != '{' {
			return Runbook{}, Fail("invalid_runbook")
		}
		timeout, sudo := DefaultTimeout, false
		if t, ok := pyjson.Get(item, "timeout"); ok {
			n, isInt := pyInt(t)
			if !isInt || n < 1 || n > MaxTimeout {
				return Runbook{}, Fail("invalid_runbook")
			}
			timeout = int(n)
		}
		if s, ok := pyjson.Get(item, "sudo"); ok {
			b, isBool := pyBool(s)
			if !isBool {
				return Runbook{}, Fail("invalid_runbook")
			}
			sudo = b
		}
		name, err := text(item, "name", MaxNameBytes)
		if err != nil {
			return Runbook{}, err
		}
		command, err := text(item, "command", MaxStepCommand)
		if err != nil {
			return Runbook{}, err
		}
		b.Steps = append(b.Steps, Step{Name: name, Command: command, Timeout: timeout, Sudo: sudo})
	}
	b.StopOnError = defaultStopFlag
	if s, ok := pyjson.Get(v, "stop_on_error"); ok {
		stop, isBool := pyBool(s)
		if !isBool {
			return Runbook{}, Fail("invalid_runbook")
		}
		b.StopOnError = stop
	}
	if _, ok := pyjson.Get(v, "id"); ok {
		id, err := text(v, "id", MaxIDBytes)
		if err != nil {
			return Runbook{}, err
		}
		b.ID = id
	} else {
		b.ID = newUUID()
	}
	name, err := text(v, "name", MaxNameBytes)
	if err != nil {
		return Runbook{}, err
	}
	b.Name = name
	return b, nil
}

// text is text() of automation_store.py for the member of obj: a string
// without NUL that is not blank and has at most maximum UTF-8 bytes.
func text(obj jsontext.Value, member string, maximum int) (string, error) {
	v, ok := pyjson.Get(obj, member)
	if !ok {
		return "", Fail("invalid_request")
	}
	s, ok := pyString(v)
	if !ok || !validText(s, maximum, false) {
		return "", Fail("invalid_request")
	}
	return s, nil
}

func validText(s string, maximum int, empty bool) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0) && len(s) <= maximum &&
		(empty || strings.TrimFunc(s, pyIsSpace) != "")
}

// pyIsSpace is str.isspace(): Unicode white space and the separators
// U+001C to U+001F.
func pyIsSpace(r rune) bool {
	return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
}

func pyString(v jsontext.Value) (string, bool) {
	if v.Kind() != '"' {
		return "", false
	}
	return unquote(v)
}

// pyInt reports a JSON integer as Python's json module reads it: a
// number written without fraction or exponent. Booleans are not.
func pyInt(v jsontext.Value) (int64, bool) {
	if v.Kind() != '0' || strings.ContainsAny(string(v), ".eE") {
		return 0, false
	}
	n, err := strconv.ParseInt(string(v), 10, 64)
	if err != nil {
		// Larger integers are out of every range checked here.
		if strings.HasPrefix(string(v), "-") {
			return -1 << 62, true
		}
		return 1 << 62, true
	}
	return n, true
}

func pyBool(v jsontext.Value) (bool, bool) {
	switch v.Kind() {
	case 't':
		return true, true
	case 'f':
		return false, true
	}
	return false, false
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:])
}

package legacy

import (
	"bytes"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

// RecoveryCheck is DATA_DIR/recovery-check.json, the notice Python shows
// after an export was restored (migration specification A07,
// app/customer_workflows.py).
type RecoveryCheck struct {
	// Present reports that the file exists.
	Present bool
	// RestoredAt is the notice's restore time as stored, or "" when Python
	// shows no notice.
	RestoredAt string
	// Malformed reports a file that Python treats as absent: too long, not
	// UTF-8, not JSON, or without a valid restored_at. It is FLAG in the
	// report.
	Malformed bool
}

// Limits of app/customer_workflows.py _restore_marker and
// valid_recovery_timestamp, in characters.
const (
	recoveryCheckChars     = 512
	recoveryTimestampChars = 64
	// recoveryCheckBytes is the most bytes recoveryCheckChars characters
	// can take; a longer file has more characters than Python accepts.
	recoveryCheckBytes = 4 * (recoveryCheckChars + 1)
)

// RecoveryCheck reads the notice exactly as Python's _restore_marker does:
// at most 512 characters after universal newline translation, a JSON
// object whose restored_at is a string of 1 to 64 characters that
// datetime.fromisoformat parses with a UTC offset. Anything else reads as
// no notice. Only an unsafe path is an error. After an export restore
// (Restored with RestoreExport) the notice is the one Python writes at
// the end of the restore.
func (s *Source) RecoveryCheck() (RecoveryCheck, error) {
	if s.restored != nil && s.restored.mode == RestoreExport {
		return RecoveryCheck{Present: true, RestoredAt: pythonUTCISOFormat(s.restored.restoredAt)}, nil
	}
	info, err := lstatChain(s.root, "recovery-check.json")
	if errors.Is(err, ErrNotFound) {
		return RecoveryCheck{}, nil
	}
	if err != nil {
		return RecoveryCheck{}, err
	}
	if !info.Mode().IsRegular() {
		return RecoveryCheck{}, fmt.Errorf("%w: %q", ErrUnsafePath, "recovery-check.json")
	}
	out := RecoveryCheck{Present: true, Malformed: true}
	if info.Size() > recoveryCheckBytes {
		return out, nil
	}
	data, err := readLimited(s.root, "recovery-check.json", recoveryCheckBytes)
	if err != nil {
		return RecoveryCheck{}, err
	}
	if at, ok := parseRecoveryCheck(data); ok {
		out.RestoredAt, out.Malformed = at, false
	}
	return out, nil
}

func parseRecoveryCheck(data []byte) (string, bool) {
	if !utf8.Valid(data) {
		return "", false
	}
	// Text mode with universal newlines: "\r\n" and "\r" read as one
	// character each.
	text := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	if utf8.RuneCount(text) > recoveryCheckChars {
		return "", false
	}
	// json.loads keeps the last of duplicate names.
	var doc map[string]jsontext.Value
	if json.Unmarshal(data, &doc, jsontext.AllowDuplicateNames(true)) != nil || doc == nil {
		return "", false
	}
	var at string
	if json.Unmarshal(doc["restored_at"], &at) != nil || at == "" || utf8.RuneCountInString(at) > recoveryTimestampChars {
		return "", false
	}
	dt, err := pythonFromISOFormat(at)
	if err != nil || !dt.hasOffset {
		return "", false
	}
	return at, true
}

// pythonUTCISOFormat is datetime.now(timezone.utc).isoformat() for t:
// microseconds only when not zero, offset "+00:00".
func pythonUTCISOFormat(t time.Time) string {
	t = t.UTC()
	out := t.Format("2006-01-02T15:04:05")
	if us := t.Nanosecond() / 1000; us != 0 {
		out += fmt.Sprintf(".%06d", us)
	}
	return out + "+00:00"
}

package automation

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// permSnapshot is permission_snapshot of app/file_mutations.py: what a
// permission change compares before it writes.
type permSnapshot struct {
	Mode     string // three octal digits
	Special  uint32 // set-id and sticky bits
	Dir      bool
	Size     int64
	Modified int64 // whole seconds, as SFTP reports them
	MTimeNS  int32
	UID, GID int64 // -1 when not reported
}

func snapshotOf(e PermEntry) (permSnapshot, error) {
	const typeBits, dirBits, regBits = 0o170000, 0o040000, 0o100000
	t := e.Mode & typeBits
	if (t != dirBits && t != regBits) || e.Size < 0 {
		return permSnapshot{}, fault.New(fault.UnsupportedOperation, "")
	}
	s := permSnapshot{Mode: fmt.Sprintf("%03o", e.Mode&0o777), Special: e.Mode & 0o7000, Dir: t == dirBits,
		Size: e.Size, UID: -1, GID: -1}
	if !e.ModTime.IsZero() {
		s.Modified, s.MTimeNS = e.ModTime.Unix(), int32(e.ModTime.Nanosecond()) // #nosec G115 -- below 1e9
	}
	if e.UID != nil {
		s.UID = int64(*e.UID)
	}
	if e.GID != nil {
		s.GID = int64(*e.GID)
	}
	return s, nil
}

func (s permSnapshot) objectType() string {
	if s.Dir {
		return "directory"
	}
	return "file"
}

// members are the snapshot as the page receives it.
func (s permSnapshot) members() []pyjson.Member {
	out := []pyjson.Member{
		{Name: "mode", Value: pyjson.String(s.Mode)},
		{Name: "special_bits", Value: jsontext.Value(strconv.FormatUint(uint64(s.Special), 10))},
		{Name: "object_type", Value: pyjson.String(s.objectType())},
		{Name: "size", Value: jsontext.Value(strconv.FormatInt(s.Size, 10))},
		{Name: "modified", Value: jsontext.Value(modifiedText(s))},
	}
	if s.UID >= 0 {
		out = append(out, pyjson.Member{Name: "uid", Value: jsontext.Value(strconv.FormatInt(s.UID, 10))})
	}
	if s.GID >= 0 {
		out = append(out, pyjson.Member{Name: "gid", Value: jsontext.Value(strconv.FormatInt(s.GID, 10))})
	}
	return out
}

func modifiedText(s permSnapshot) string {
	if s.MTimeNS == 0 {
		return strconv.FormatInt(s.Modified, 10)
	}
	return strconv.FormatFloat(float64(s.Modified)+float64(s.MTimeNS)/1e9, 'f', -1, 64)
}

// ParseMode is parse_mode: exactly three octal digits.
func ParseMode(mode string) (uint32, error) {
	if len(mode) != 3 || strings.Trim(mode, "01234567") != "" {
		return 0, fault.New(fault.InvalidRequest, "")
	}
	n, _ := strconv.ParseUint(mode, 8, 32)
	return uint32(n), nil
}

// validLeaf is validate_leaf for a name the server listed.
func validLeaf(name string) bool {
	if name == "" || len(name) > 255 || !utf8.ValidString(name) || name == "." || name == ".." || strings.ContainsAny(name, `/\`) {
		return false
	}
	return !strings.ContainsFunc(name, func(r rune) bool { return r < 0x20 || r >= 0x7f && r <= 0x9f })
}

// metadataToken binds the inspected state of one object to the user, the
// source and the path for permMetadataTTL ("<stamp>.<digest>.<mac>", as
// issue_metadata_token). The key lives only in memory: a token is good
// for a minute, so a restart only asks the user to inspect again.
func (j *PermissionJobs) metadataToken(c PermCaller, sourceID, p string, s permSnapshot) string {
	body := strconv.FormatInt(j.o.Now().Unix(), 10) + "." + metadataDigest(c, sourceID, p, s)
	return body + "." + j.sign(body)
}

func metadataDigest(c PermCaller, sourceID, p string, s permSnapshot) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%d\x00%s\x00%s\x00%+v", c.P.UserID, sourceID, p, s))
	return hex.EncodeToString(sum[:])
}

func (j *PermissionJobs) sign(body string) string {
	m := hmac.New(sha256.New, j.tokenKey)
	m.Write([]byte("file-permissions-v1\x00" + body))
	return hex.EncodeToString(m.Sum(nil))
}

func (j *PermissionJobs) verifyToken(token string, c PermCaller, sourceID, p string, s permSnapshot) error {
	changed := fault.New(fault.MetadataChanged, "")
	parts := strings.Split(token, ".")
	if len(token) > 512 || len(parts) != 3 || len(parts[0]) == 0 || len(parts[0]) > 12 || len(parts[1]) != 64 || len(parts[2]) != 64 {
		return changed
	}
	stamp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return changed
	}
	age := j.o.Now().Unix() - stamp
	if age < 0 || age > int64(permMetadataTTL.Seconds()) {
		return changed
	}
	if !hmac.Equal([]byte(parts[2]), []byte(j.sign(parts[0]+"."+parts[1]))) ||
		!hmac.Equal([]byte(parts[1]), []byte(metadataDigest(c, sourceID, p, s))) {
		return changed
	}
	return nil
}

// Inspect returns the permissions of one object with the metadata token a
// change must present (get_file_permissions).
func (j *PermissionJobs) Inspect(ctx context.Context, c PermCaller, sourceID, raw string) (jsontext.Value, error) {
	p, err := j.o.Sources.Clean(raw)
	if err != nil {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	src, _, release, err := j.o.Sources.Hold(ctx, c.P, sourceID)
	if err != nil {
		return nil, err
	}
	defer release()
	e, err := src.Lstat(ctx, p)
	if err != nil {
		return nil, mutationFailure(err, false)
	}
	s, err := snapshotOf(e)
	if err != nil {
		return nil, err
	}
	m := append(s.members(), pyjson.Member{Name: "path", Value: pyjson.String(p)},
		pyjson.Member{Name: "metadata_token", Value: pyjson.String(j.metadataToken(c, sourceID, p, s))})
	return pyjson.Object(m), nil
}

// modeMismatch is MODE_MISMATCH with the mode the server reported
// (actual_mode).
func modeMismatch(actual uint32) error {
	e := fault.New(fault.ModeMismatch, "")
	e.Details = map[string]any{"actual_mode": fmt.Sprintf("%03o", actual&0o777)}
	return e
}

// Change sets the mode of one object whose state still matches the
// inspected metadata token (set_file_permissions). Set-id and sticky bits
// are refused; an unchanged mode writes nothing.
func (j *PermissionJobs) Change(ctx context.Context, c PermCaller, sourceID, raw, mode, token string) (jsontext.Value, error) {
	p, err := j.o.Sources.Clean(raw)
	if err != nil {
		return nil, fault.New(fault.InvalidRequest, "")
	}
	want, err := ParseMode(mode)
	if err != nil {
		return nil, err
	}
	out, oldMode, err := j.change(ctx, c, sourceID, p, want, token)
	result := "COMPLETED"
	if err != nil {
		result = string(fault.CodeOf(err))
	}
	j.auditChange(c, sourceID, "chmod", result, p, oldMode, mode, err)
	return out, err
}

func (j *PermissionJobs) change(ctx context.Context, c PermCaller, sourceID, p string, want uint32, token string) (jsontext.Value, string, error) {
	src, _, release, err := j.o.Sources.Hold(ctx, c.P, sourceID)
	if err != nil {
		return nil, "", err
	}
	defer release()
	e, err := src.Lstat(ctx, p)
	if err != nil {
		return nil, "", mutationFailure(err, false)
	}
	before, err := snapshotOf(e)
	if err != nil {
		return nil, "", err
	}
	if err := j.verifyToken(token, c, sourceID, p, before); err != nil {
		return nil, before.Mode, err
	}
	if before.Special != 0 {
		return nil, before.Mode, fault.New(fault.UnsupportedOperation, "")
	}
	reply := func(s permSnapshot) jsontext.Value {
		return pyjson.Object(append(s.members(), pyjson.Member{Name: "old_mode", Value: pyjson.String(before.Mode)},
			pyjson.Member{Name: "path", Value: pyjson.String(p)}))
	}
	if before.Mode == fmt.Sprintf("%03o", want) {
		return reply(before), before.Mode, nil
	}
	if err := src.Chmod(ctx, p, want); err != nil {
		if fault.CodeOf(err) == fault.ModeMismatch {
			if e, err2 := src.Lstat(ctx, p); err2 == nil {
				return nil, before.Mode, modeMismatch(e.Mode)
			}
		}
		return nil, before.Mode, mutationFailure(err, true)
	}
	e, err = src.Lstat(ctx, p)
	if err != nil {
		return nil, before.Mode, fault.New(fault.OutcomeUnknown, "")
	}
	after, err := snapshotOf(e)
	if err != nil || after.Mode != fmt.Sprintf("%03o", want) || after.Special != 0 {
		return nil, before.Mode, modeMismatch(e.Mode)
	}
	return reply(after), before.Mode, nil
}

// mutationFailure is mutation_failure: the definite file codes pass, a
// failure after the change was sent is OUTCOME_UNKNOWN, everything else
// OPERATION_FAILED. Remote text never reaches the page.
func mutationFailure(err error, uncertain bool) error {
	if fault.CodeOf(err) == fault.ModeMismatch && fault.DetailsOf(err) != nil {
		return err
	}
	switch c := fault.CodeOf(err); c {
	case fault.FilePermissionDenied, fault.FileNotFound, fault.FileConflict, fault.UnsupportedOperation,
		fault.MetadataChanged, fault.OutcomeUnknown, fault.ModeMismatch, fault.InvalidRequest,
		fault.SourceUnavailable, fault.FileTimeout:
		return fault.New(c, "")
	}
	if uncertain {
		return fault.New(fault.OutcomeUnknown, "")
	}
	return fault.New(fault.OperationFailed, "")
}

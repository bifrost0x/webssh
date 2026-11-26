package files

import (
	"bytes"
	"context"
	"fmt"
	"maps"

	"github.com/bifrost0x/webssh/internal/fault"
)

// EditDocument is a file opened for the editor (edit_data).
type EditDocument struct {
	Path     string
	Text     string // line endings as LF
	Size     int64
	Encoding Encoding
	Newline  Newline
	Revision string
	Original []byte
	Endpoint string
}

func (s *Service) mib() int64 { return s.opts.MaxEditorBytes / (1 << 20) }

func (s *Service) tooLargeToEdit() error {
	return fault.New(fault.FileTooLarge, fmt.Sprintf("File too large to edit. Maximum: %dMB", s.mib()))
}

// OpenEdit reads a whole text file for the editor (open_file_for_edit).
// Nothing is cut: a file above MAX_EDITOR_FILE_SIZE or with binary
// content is refused, so a later save cannot shorten or damage it.
func (s *Service) OpenEdit(ctx context.Context, c Caller, sourceID, path string) (EditDocument, error) {
	p, err := Clean(path)
	if err != nil {
		return EditDocument{}, err
	}
	r, err := s.resolve(ctx, c, sourceID, CapEdit)
	if err != nil {
		return EditDocument{}, err
	}
	defer r.release()
	raw, err := s.readWhole(ctx, r, p, fmt.Sprintf("File too large to edit. Maximum: %dMB", s.mib()))
	if err != nil {
		return EditDocument{}, err
	}
	text, enc, binary := Decode(raw)
	if binary {
		return EditDocument{}, fault.New(fault.FileBinary, "Binary file cannot be edited.")
	}
	return EditDocument{
		Path: path, Text: EditorText(text), Size: int64(len(raw)), Encoding: enc, Newline: DetectNewline(raw),
		Revision: Revision(raw), Original: raw, Endpoint: r.desc.Endpoint,
	}, nil
}

// SaveRequest is an editor save (save_file).
type SaveRequest struct {
	SourceID, Path, Content    string
	Encoding, Newline          string // "utf-8" and "lf" when empty
	ExpectedRevision, Strategy string // Strategy: "atomic" when empty
	Challenge                  string // save_challenge of an earlier refusal
}

// Saved is the outcome of a save that installed the new content.
type Saved struct {
	Path           string
	Revision       string
	Warning        string
	RecoveryLeaves []string
}

// Save writes editor text back (save_file): the file must still have the
// revision the editor opened, the text is encoded for the file's encoding
// and line endings, and the content is replaced in one step. On SMB a
// refusal with SMB_RECOVERABLE_REPLACE_REQUIRED carries a save challenge
// that lets the same save be sent once more with recoverable_swap without
// a second charge to the editor budget.
func (s *Service) Save(ctx context.Context, c Caller, req SaveRequest) (Saved, error) {
	if req.Encoding == "" {
		req.Encoding = string(EncodingUTF8)
	}
	if req.Newline == "" {
		req.Newline = string(NewlineLF)
	}
	strategy := Strategy(req.Strategy)
	switch strategy {
	case "":
		strategy = StrategyAtomic
	case StrategyAtomic, StrategyRecoverableSwap:
	default:
		return Saved{}, fault.New(fault.InvalidRequest, "Invalid replacement strategy.")
	}
	req.Strategy = string(strategy)
	p, err := CleanTarget(req.Path)
	if err != nil {
		return Saved{}, err
	}
	if int64(len(req.Content)) > s.opts.MaxEditorBytes {
		return Saved{}, fault.New(fault.FileTooLarge, fmt.Sprintf("File too large to save. Maximum size: %dMB", s.mib()))
	}
	fp := fingerprint(c.owner(), req)
	exempt := strategy == StrategyRecoverableSwap && req.Challenge != "" && s.challenges.consume(req.Challenge, fp)
	if !exempt {
		if err := s.editor.charge(c.P.UserID, int64(max(len(req.Content), 1))); err != nil {
			return Saved{}, err
		}
	}
	r, err := s.resolve(ctx, c, req.SourceID, CapEdit)
	if err != nil {
		return Saved{}, err
	}
	defer r.release()
	out, err := s.save(ctx, r, p, req, strategy)
	if fault.Is(err, fault.SMBRecoverableReplaceNeed) && strategy == StrategyAtomic {
		err = withDetail(err, "save_challenge", s.challenges.issue(fp))
	}
	s.auditResult(c, r, "edit_save", saveAuditResult(strategy, out, err), p, int64(len(req.Content)))
	return out, err
}

func (s *Service) save(ctx context.Context, r resolved, p string, req SaveRequest, strategy Strategy) (Saved, error) {
	if req.ExpectedRevision == "" {
		return Saved{}, errEditConflict
	}
	original, err := s.readWhole(ctx, r, p, fmt.Sprintf("File too large to edit. Maximum: %dMB", s.mib()))
	if err != nil {
		return Saved{}, err
	}
	if Revision(original) != req.ExpectedRevision {
		return Saved{}, errEditConflict
	}
	data, err := EncodeEditorText(req.Content, Encoding(req.Encoding), Newline(req.Newline), original)
	if err != nil {
		return Saved{}, err
	}
	if int64(len(data)) > s.opts.MaxEditorBytes {
		return Saved{}, s.tooLargeToEdit()
	}
	res, err := r.b.Write(ctx, p, bytes.NewReader(data), WriteOptions{
		ExpectedRevision: req.ExpectedRevision, Strategy: strategy, FollowSymlink: true,
		Size: int64(len(data)), MaxBytes: s.opts.MaxEditorBytes,
	})
	switch {
	case fault.Is(err, fault.OutcomeUnknown):
		return Saved{}, fault.Wrap(fault.SaveOutcomeUnknown, err,
			"The save result could not be confirmed. Keep your draft and reopen the file before saving again.")
	case fault.Is(err, fault.MetadataChanged):
		return Saved{}, fault.Wrap(fault.EditConflict, err, errEditConflict.Message)
	case err != nil:
		return Saved{}, err
	}
	return Saved{Path: req.Path, Revision: res.Revision, Warning: res.Warning, RecoveryLeaves: res.RecoveryLeaves}, nil
}

var errEditConflict = fault.New(fault.EditConflict, "The file changed on the server. Reopen it before saving.")

// withDetail returns err as a copy with one more detail.
func withDetail(err error, key string, value any) error {
	fe, ok := fault.From(err)
	if !ok {
		return err
	}
	c := *fe
	c.Details = map[string]any{}
	maps.Copy(c.Details, fe.Details)
	c.Details[key] = value
	return &c
}

// saveAuditResult names the outcome of a save as the Python audit did.
func saveAuditResult(strategy Strategy, out Saved, err error) string {
	switch {
	case err == nil && out.Warning != "":
		return "COMPLETED_WITH_RECOVERY_BACKUP"
	case err == nil && strategy == StrategyRecoverableSwap:
		return "RECOVERABLE_REPLACE_COMPLETED"
	case err == nil:
		return "COMPLETED"
	}
	switch fault.CodeOf(err) {
	case fault.SMBRecoverableReplaceNeed:
		return "RECOVERABLE_REPLACE_REQUIRED"
	case fault.SMBRecoverableReplaceFail:
		return "RECOVERABLE_REPLACE_FAILED_ROLLED_BACK"
	case fault.SMBRecoveryRequired:
		return "RECOVERY_REQUIRED"
	case fault.EditConflict:
		return "EDIT_CONFLICT"
	}
	return "FAILED"
}

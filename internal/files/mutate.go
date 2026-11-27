package files

import (
	"context"
	"path"
	"strings"
	"unicode"

	"github.com/bifrost0x/webssh/internal/fault"
)

var (
	errMove        = fault.New(fault.InvalidRequest, "The move request is invalid.")
	errDestination = fault.New(fault.FileConflict, "A file or folder already exists at the destination.")
)

// Mkdir creates one directory (create_directory).
func (s *Service) Mkdir(ctx context.Context, c Caller, sourceID, dir string) (string, error) {
	p, err := s.cleanTarget(dir)
	if err != nil {
		return "", err
	}
	r, err := s.resolve(ctx, c, sourceID, CapMkdir)
	if err != nil {
		return "", err
	}
	defer r.release()
	err = r.b.Mkdir(ctx, p)
	s.audit(c, r, "mkdir", err, p, 0)
	return dir, err
}

// CreateFile creates an empty file name in parent and never replaces an
// existing one (create_file).
func (s *Service) CreateFile(ctx context.Context, c Caller, sourceID, parent, name string) (string, error) {
	dir, err := s.clean(parent)
	if err != nil {
		return "", err
	}
	p, err := Join(dir, name)
	if err == nil {
		p, err = s.cleanTarget(p)
	}
	if err != nil {
		return "", err
	}
	r, err := s.resolve(ctx, c, sourceID, CapCreateFile)
	if err != nil {
		return "", err
	}
	defer r.release()
	_, err = r.b.Write(ctx, p, strings.NewReader(""), WriteOptions{Exclusive: true, Size: 0, MaxBytes: 1})
	result := "COMPLETED"
	if err != nil {
		result = strings.ToUpper(string(fault.CodeOf(err)))
	}
	s.auditResult(c, r, "create_file", result, p, 0)
	return p, err
}

// Rename moves an item within its source (rename_file). It never replaces:
// an existing destination is a conflict. Moving an item onto itself or
// into its own subtree is refused; on a case-insensitive source the names
// compare case-folded.
func (s *Service) Rename(ctx context.Context, c Caller, sourceID, oldPath, newPath string) error {
	from, err1 := s.cleanTarget(oldPath)
	to, err2 := s.cleanTarget(newPath)
	if err1 != nil || err2 != nil {
		return errMove
	}
	// A move keeps its name; only a changed name must not be blank.
	if leaf := path.Base(to); leaf != path.Base(from) && strings.TrimFunc(leaf, unicode.IsSpace) == "" {
		return errMove
	}
	r, err := s.resolve(ctx, c, sourceID, CapRename)
	if err != nil {
		return err
	}
	defer r.release()
	fold := r.caps.CaseInsensitive
	if same(from, to, fold) || Within(from, to, fold) {
		return errMove
	}
	err = s.rename(ctx, r, from, to)
	s.audit(c, r, "rename", err, from, 0, "destination_target_host", r.desc.Endpoint, "destination_filename", baseName(to))
	return err
}

func (s *Service) rename(ctx context.Context, r resolved, from, to string) error {
	switch _, err := r.b.Stat(ctx, to, false); {
	case err == nil:
		return errDestination
	case !fault.Is(err, fault.FileNotFound):
		return err
	}
	err := r.b.Rename(ctx, from, to)
	if fault.Is(err, fault.FileConflict) {
		return errDestination
	}
	return err
}

func same(a, b string, fold bool) bool {
	if fold {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Delete removes a file, a link or a directory with its content, within
// the default budget (delete_item). The root of a source is never
// deleted.
func (s *Service) Delete(ctx context.Context, c Caller, sourceID, target string) error {
	p, err := s.cleanTarget(target)
	if err != nil {
		return err
	}
	r, err := s.resolve(ctx, c, sourceID, CapDelete|CapRecursive)
	if err != nil {
		return err
	}
	defer r.release()
	err = r.b.Remove(ctx, p, true, Budget{MaxMembers: s.opts.MaxMembers}.WithDefaults())
	s.audit(c, r, "delete", err, p, 0)
	return err
}

// CloseSource ends a Quick SFTP or SMB source of the caller
// (file_source_disconnect).
func (s *Service) CloseSource(c Caller, sourceID string) error {
	if _, _, err := ParseSourceID(sourceID); err != nil {
		return err
	}
	return s.reg.Close(c.P, sourceID)
}

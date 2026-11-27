package files

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/bifrost0x/webssh/internal/fault"
)

// OpenFollow opens the regular file at p for reading and follows a
// symbolic link to a regular file, as the Python release did when it
// showed, edited or downloaded a file such as sites-enabled/*. Every read
// of the workspace goes through it (preview, editor, image; transfers use
// it for downloads). Backend.Open itself never follows a link; the target
// comes from Stat with follow, whose Entry.Path is the canonical path of
// the final target. A link to a directory, a dangling link or a target
// the backend refuses (SMB reparse points) is not opened. It returns the
// path that was opened.
func OpenFollow(ctx context.Context, b Backend, p string, r Range) (Reader, string, error) {
	rd, err := b.Open(ctx, p, r)
	if err == nil || !fault.Is(err, fault.UnsupportedOperation) {
		return rd, p, err
	}
	e, serr := b.Stat(ctx, p, false)
	if serr != nil || !e.IsSymlink {
		return nil, "", err
	}
	t, serr := b.Stat(ctx, p, true)
	if serr != nil {
		return nil, "", serr
	}
	if t.IsDir || t.IsSymlink || t.Path == "" || t.Path == p {
		return nil, "", err
	}
	rd, err = b.Open(ctx, t.Path, r)
	return rd, t.Path, err
}

// readAtMost reads up to n bytes; more fails with fault.FileTooLarge.
func readAtMost(r io.Reader, n int64, tooLarge error) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, readFailure(err)
	}
	if int64(len(data)) > n {
		return nil, tooLarge
	}
	return data, nil
}

// readFailure keeps a classified backend error and hides any other.
func readFailure(err error) error {
	if _, ok := fault.From(err); ok {
		return err
	}
	return fault.Wrap(fault.OperationFailed, err, "")
}

// PreviewRequest are the preview controls of the page; nil takes the
// default (max_bytes 512000, offset 0, no tail).
type PreviewRequest struct {
	SourceID, Path              string
	Offset, MaxBytes, TailLines *int64
}

// Preview is a text preview (preview_data).
type Preview struct {
	Path      string
	Text      string
	Binary    bool
	Encoding  Encoding
	Size      int64 // size of the file
	ReadSize  int64 // bytes shown
	Truncated bool
	Offset    int64
}

func (s *Service) previewOptions(q PreviewRequest) (maxBytes, offset, tail int64, err error) {
	maxBytes, offset = DefaultMaxPreviewBytes, 0
	bad := func(msg string) error { return fault.New(fault.InvalidRequest, "Invalid preview options: "+msg) }
	if q.MaxBytes != nil {
		if maxBytes = *q.MaxBytes; maxBytes <= 0 {
			return 0, 0, 0, bad("max_bytes must be a positive integer")
		}
	}
	if q.Offset != nil {
		if offset = *q.Offset; offset < 0 {
			return 0, 0, 0, bad("offset must be a non-negative integer")
		}
	}
	if q.TailLines != nil {
		if tail = *q.TailLines; tail <= 0 {
			return 0, 0, 0, bad("tail_lines must be a positive integer")
		}
	}
	switch {
	case offset > s.opts.MaxSupportedFileSize:
		return 0, 0, 0, bad("offset exceeds the supported file size")
	case tail > s.opts.MaxPreviewTailLines:
		return 0, 0, 0, bad("tail_lines exceeds the configured limit")
	}
	return min(maxBytes, s.opts.MaxPreviewBytes), offset, tail, nil
}

// Preview reads the start of a file, a part from Offset or its last lines
// (preview_file), decoded with the rule of the editor (D-23).
func (s *Service) Preview(ctx context.Context, c Caller, q PreviewRequest) (Preview, error) {
	maxBytes, offset, tail, err := s.previewOptions(q)
	if err != nil {
		return Preview{}, err
	}
	p, err := s.clean(q.Path)
	if err != nil {
		return Preview{}, err
	}
	r, err := s.resolve(ctx, c, q.SourceID, CapPreview)
	if err != nil {
		return Preview{}, err
	}
	defer r.release()
	start := offset
	if tail > 0 {
		e, err := r.b.Stat(ctx, p, true)
		if err != nil {
			return Preview{}, err
		}
		start = max(0, e.Size-maxBytes)
	}
	rd, _, err := OpenFollow(ctx, r.b, p, Range{Offset: start, Length: maxBytes})
	if err != nil {
		return Preview{}, err
	}
	defer func() { _ = rd.Close() }()
	size := rd.Entry().Size
	if size > s.opts.MaxSupportedFileSize {
		return Preview{}, fault.New(fault.FileTooLarge,
			fmt.Sprintf("File too large (%d bytes). Maximum supported size is %d bytes.", size, s.opts.MaxSupportedFileSize))
	}
	content, err := readAtMost(rd, maxBytes, fault.New(fault.FileTooLarge, "Preview exceeds the configured size limit."))
	if err != nil {
		return Preview{}, err
	}
	truncated := size > maxBytes
	if tail > 0 {
		if lines := bytes.Split(content, []byte("\n")); int64(len(lines)) > tail {
			content = bytes.Join(lines[int64(len(lines))-tail:], []byte("\n"))
			truncated = true
		}
	}
	text, enc, binary := Decode(content)
	return Preview{
		Path: q.Path, Text: text, Binary: binary, Encoding: enc, Size: size,
		ReadSize: int64(len(content)), Truncated: truncated, Offset: offset,
	}, nil
}

// Image reads a whole file of at most MAX_EDITOR_FILE_SIZE bytes for the
// image preview (download_file_binary with for_preview).
func (s *Service) Image(ctx context.Context, c Caller, sourceID, path string) ([]byte, error) {
	p, err := s.clean(path)
	if err != nil {
		return nil, err
	}
	r, err := s.resolve(ctx, c, sourceID, CapPreview)
	if err != nil {
		return nil, err
	}
	defer r.release()
	data, err := s.readWhole(ctx, r, p, "File too large to preview.")
	s.audit(c, r, "binary_preview", err, p, int64(len(data)))
	return data, err
}

// readWhole reads a regular file of at most MaxEditorBytes.
func (s *Service) readWhole(ctx context.Context, r resolved, p, tooLarge string) ([]byte, error) {
	rd, _, err := OpenFollow(ctx, r.b, p, Range{Length: -1})
	if err != nil {
		return nil, err
	}
	defer func() { _ = rd.Close() }()
	limit := fault.New(fault.FileTooLarge, tooLarge)
	if rd.Entry().Size > s.opts.MaxEditorBytes {
		return nil, limit
	}
	return readAtMost(rd, s.opts.MaxEditorBytes, limit)
}

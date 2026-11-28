package audit

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Reading the log back for the view and the export (E34): Python and Go
// lines alike, newest first, in chunks, so no file is ever read whole.

const (
	readChunk = 64 << 10
	// MaxLineBytes bounds one line read back. A longer line is counted as
	// scanned and skipped; the Python release read it whole (fix).
	MaxLineBytes = 1 << 20
)

// lineFunc receives one line; returning false stops the scan.
type lineFunc func(line []byte) bool

// newestFirst calls fn for every non-empty line of path from the last
// to the first, like _iter_log_lines_newest_first. It reports whether fn
// stopped the scan.
func newestFirst(path string, fn lineFunc) (stopped bool, err error) {
	// Without following a link, and checked on the opened file, so no
	// link can be swapped in after the check; O_NONBLOCK keeps a FIFO
	// from blocking the open.
	f, err := os.OpenFile(path, os.O_RDONLY|openNoFollow, 0) // #nosec G304 -- path is a file of the audit log directory
	if err != nil {
		if isLink(err) {
			return false, errNotRegular
		}
		return false, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil {
		return false, err
	} else if !st.Mode().IsRegular() {
		return false, errNotRegular
	}
	pos, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return false, err
	}
	var pending []byte
	overlong := false
	buf := make([]byte, readChunk)
	emit := func(line []byte, long bool) bool {
		if len(line) == 0 && !long {
			return true
		}
		if long {
			return fn(nil)
		}
		return fn(line)
	}
	for pos > 0 {
		n := int64(len(buf))
		n = min(n, pos)
		pos -= n
		chunk := buf[:n]
		if _, err := f.ReadAt(chunk, pos); err != nil {
			return false, err
		}
		for {
			i := bytes.LastIndexByte(chunk, '\n')
			if i < 0 {
				break
			}
			tail := chunk[i+1:]
			line := slices.Concat(tail, pending)
			long := overlong || len(line) > MaxLineBytes
			if !emit(line, long) {
				return true, nil
			}
			pending, overlong = nil, false
			chunk = chunk[:i]
		}
		if !overlong {
			pending = slices.Concat(chunk, pending)
			if len(pending) > MaxLineBytes {
				pending, overlong = nil, true
			}
		}
	}
	if len(pending) > 0 || overlong {
		if !emit(pending, overlong) {
			return true, nil
		}
	}
	return false, nil
}

// candidateFiles is _candidate_files of app/audit_export.py: the log,
// then every "<name>.*" file ordered by its last suffix when that is a
// number and first otherwise. Only regular files are read; the Python
// release followed links (fix). Files with the same key keep name order,
// where Python kept the directory order.
func candidateFiles(path string) ([]string, error) {
	dir, base := filepath.Dir(path), filepath.Base(path)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	type cand struct {
		name string
		key  int
	}
	var rotated []cand
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), base+".") {
			continue
		}
		key := -1
		if i := strings.LastIndexByte(e.Name(), '.'); i > 0 {
			if n, ok := num(e.Name()[i+1:]); ok {
				key = n
			}
		}
		rotated = append(rotated, cand{e.Name(), key})
	}
	slices.SortStableFunc(rotated, func(a, b cand) int { return a.key - b.key })
	out := []string{path}
	for _, c := range rotated {
		out = append(out, filepath.Join(dir, c.name))
	}
	return out, nil
}

// errNotRegular is a log path that is a link, a FIFO or anything else
// than a regular file; the reader skips it.
var errNotRegular = errors.New("audit: not a regular file")

// scanFiles calls fn for the lines of files, newest first, at most limit
// lines in all. It reports whether a line beyond the limit exists. A file
// that disappears is skipped.
func scanFiles(files []string, limit int, fn lineFunc) (truncated bool, err error) {
	scanned := 0
	for _, path := range files {
		stopped, err := newestFirst(path, func(line []byte) bool {
			if scanned >= limit {
				truncated = true
				return false
			}
			scanned++
			return fn(line)
		})
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotRegular) {
			continue
		}
		if err != nil {
			return truncated, err
		}
		if stopped {
			return truncated, nil
		}
	}
	return false, nil
}

// numbered are the files the view reads: the log and its rotated files
// up to the backup count (read_audit_logs).
func numbered(path string, backups int) []string {
	out := []string{path}
	for i := 1; i <= backups; i++ {
		out = append(out, path+"."+strconv.Itoa(i))
	}
	return out
}

// decodeText is bytes.decode("utf-8", errors="replace"): each maximal
// invalid subsequence becomes one U+FFFD, as CPython's decoder does.
func decodeText(b []byte) []byte {
	if utf8.Valid(b) {
		return b
	}
	out := make([]byte, 0, len(b)+8)
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r != utf8.RuneError || n > 1 {
			out = append(out, b[i:i+n]...)
			i += n
			continue
		}
		out = utf8.AppendRune(out, utf8.RuneError)
		i += invalidPrefix(b[i:])
	}
	return out
}

// invalidPrefix is the length of the maximal subpart of an ill-formed
// sequence at the start of b (at least 1).
func invalidPrefix(b []byte) int {
	lo, hi, need := byte(0x80), byte(0xbf), 0
	switch c := b[0]; {
	case c >= 0xc2 && c <= 0xdf:
		need = 1
	case c == 0xe0:
		lo, need = 0xa0, 2
	case c >= 0xe1 && c <= 0xec, c == 0xee, c == 0xef:
		need = 2
	case c == 0xed:
		hi, need = 0x9f, 2
	case c == 0xf0:
		lo, need = 0x90, 3
	case c >= 0xf1 && c <= 0xf3:
		need = 3
	case c == 0xf4:
		hi, need = 0x8f, 3
	default:
		return 1
	}
	n := 1
	for ; n <= need && n < len(b); n++ {
		if b[n] < lo || b[n] > hi {
			break
		}
		lo, hi = 0x80, 0xbf
	}
	return n
}

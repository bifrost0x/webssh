package config

import (
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

// defaultDataDir is DATA_DIR when the variable is unset, as in the
// container image and entrypoint.sh.
const defaultDataDir = "/app/data"

// pyPath is str(pathlib.PurePosixPath(s)): "." for "", repeated and
// trailing slashes and "." parts removed, exactly two leading slashes
// kept.
func pyPath(s string) string {
	if s == "" {
		return "."
	}
	root := ""
	switch {
	case strings.HasPrefix(s, "//") && !strings.HasPrefix(s, "///"):
		root = "//"
	case strings.HasPrefix(s, "/"):
		root = "/"
	}
	var parts []string
	for part := range strings.SplitSeq(s, "/") {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	if root == "" && len(parts) == 0 {
		return "."
	}
	return root + strings.Join(parts, "/")
}

// pyTempDir approximates tempfile.gettempdir(): the first of TMPDIR, TEMP
// and TMP, else /tmp. Python also probes that the directory is writable;
// the value only names the backup work area, which this preview does not
// use.
func pyTempDir(get LookupFunc) string {
	for _, name := range []string{"TMPDIR", "TEMP", "TMP"} {
		if v, ok := get(name); ok && v != "" {
			return pyPath(v)
		}
	}
	return "/tmp"
}

// pyRepr is repr() of a Python str. An invalid UTF-8 byte appears as the
// surrogate Python's surrogateescape decoding gives it.
func pyRepr(s string) string {
	quote := byte('\'')
	if strings.Contains(s, "'") && !strings.Contains(s, `"`) {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\udc%02x`, s[i])
			i++
			continue
		}
		i += size
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == rune(quote):
			b.WriteByte('\\')
			b.WriteByte(quote)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x10000:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}

// fileSystem is the part of the file system the entrypoint rules read.
type fileSystem interface {
	Lstat(name string) (fs.FileInfo, error)
	Stat(name string) (fs.FileInfo, error)
	Readlink(name string) (string, error)
	ReadFile(name string) ([]byte, error)
}

type osFS struct{}

func (osFS) Lstat(name string) (fs.FileInfo, error) { return os.Lstat(name) }
func (osFS) Stat(name string) (fs.FileInfo, error)  { return os.Stat(name) }
func (osFS) Readlink(name string) (string, error)   { return os.Readlink(name) }
func (osFS) ReadFile(name string) ([]byte, error) {
	return os.ReadFile(name) // #nosec G304 -- the secret file below the operator's DATA_DIR
}

// pyRealpath is os.path.realpath(path) of Python 3.15 (strict=False) for
// an absolute path: symbolic links are resolved where they exist, a
// missing or unreadable part is kept as written, and a link loop ends the
// resolution at the looping link.
func pyRealpath(fsys fileSystem, path string) string {
	const sep = "/"
	// rest is a stack of unresolved parts; a nil entry marks that the link
	// below it has been resolved.
	type part struct {
		name   string
		marker bool
	}
	var rest []part
	pieces := strings.Split(strings.TrimRight(path, sep), sep)
	for _, piece := range slices.Backward(pieces) {
		rest = append(rest, part{name: piece})
	}
	partCount := len(pieces)
	resolved := sep
	seen := map[string]*string{}
	for partCount > 0 {
		top := rest[len(rest)-1]
		rest = rest[:len(rest)-1]
		if top.marker {
			link := rest[len(rest)-1].name
			rest = rest[:len(rest)-1]
			target := resolved
			seen[link] = &target
			continue
		}
		partCount--
		name := top.name
		if name == "" || name == "." {
			continue
		}
		if name == ".." {
			if i := strings.LastIndex(resolved, sep); i > 0 {
				resolved = resolved[:i]
			} else {
				resolved = sep
			}
			continue
		}
		next := resolved + sep + name
		if resolved == sep {
			next = resolved + name
		}
		info, err := fsys.Lstat(next)
		if err != nil {
			resolved = next
			continue
		}
		if info.Mode()&fs.ModeSymlink == 0 {
			resolved = next
			continue
		}
		if cached, ok := seen[next]; ok {
			if cached != nil {
				resolved = *cached
				continue
			}
			resolved = next // loop
			continue
		}
		target, err := fsys.Readlink(next)
		if err != nil {
			resolved = next
			continue
		}
		if strings.HasPrefix(target, sep) {
			resolved = sep
		}
		seen[next] = nil
		rest = append(rest, part{name: next}, part{marker: true})
		targetParts := strings.Split(target, sep)
		for _, targetPart := range slices.Backward(targetParts) {
			rest = append(rest, part{name: targetPart})
		}
		partCount += len(targetParts)
	}
	return resolved
}

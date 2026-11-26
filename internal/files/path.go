package files

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Limits of the path model (FILE_CONTROL_MAX_PATH_BYTES and the leaf limit
// of app/file_mutations.py).
const (
	MaxPathBytes = 4096
	MaxNameBytes = 255
)

var errPath = fault.New(fault.InvalidRequest, "The path is invalid.")

// Clean returns the canonical form of a path the page sent for reading or
// listing: absolute, separated by single slashes, without "." segments and
// without a trailing slash. It refuses an empty path, a relative one,
// invalid UTF-8, NUL and other control characters, a ".." segment
// anywhere (before cleaning, so ".." never climbs) and more than
// MaxPathBytes. A backslash is an ordinary character of a POSIX name here;
// SMB refuses it in its own component rules.
//
// The page resolves "." and "" to Home before it asks; Clean does not.
func Clean(raw string) (string, error) {
	if raw == "" || len(raw) > MaxPathBytes || !utf8.ValidString(raw) || raw[0] != '/' {
		return "", errPath
	}
	for seg := range strings.SplitSeq(raw, "/") {
		if seg == ".." {
			return "", errPath
		}
	}
	if strings.ContainsFunc(raw, isControl) {
		return "", errPath
	}
	return path.Clean(raw), nil
}

// CleanTarget is Clean for the path of a mutation (create, write, rename,
// delete, chmod): it also refuses a leading "//", a backslash and the
// root itself, as the Python release did.
func CleanTarget(raw string) (string, error) {
	if strings.HasPrefix(raw, "//") || strings.ContainsRune(raw, '\\') {
		return "", errPath
	}
	p, err := Clean(raw)
	if err != nil {
		return "", err
	}
	if p == "/" {
		return "", errPath
	}
	return p, nil
}

// ValidName checks one leaf name the page sent for a new file, directory
// or rename target: 1 to MaxNameBytes bytes of valid UTF-8, not "." or
// "..", no slash, backslash or control character, not only white space.
func ValidName(name string) error {
	switch {
	case name == "" || len(name) > MaxNameBytes || !utf8.ValidString(name),
		name == "." || name == "..",
		strings.ContainsAny(name, `/\`),
		strings.ContainsFunc(name, isControl),
		strings.TrimFunc(name, unicode.IsSpace) == "":
		return errPath
	}
	return nil
}

// Join appends a valid leaf name to a canonical directory.
func Join(dir, name string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	p := path.Join(dir, name)
	if len(p) > MaxPathBytes {
		return "", errPath
	}
	return p, nil
}

// Within reports whether p is root or below it; both are canonical. With
// fold the comparison is case-insensitive (SMB).
func Within(root, p string, fold bool) bool {
	if fold {
		root, p = strings.ToLower(root), strings.ToLower(p)
	}
	if root == "/" || root == p {
		return strings.HasPrefix(p, root)
	}
	return strings.HasPrefix(p, root+"/")
}

// isControl matches C0, DEL and C1 characters, which the Python release
// refused in every path.
func isControl(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

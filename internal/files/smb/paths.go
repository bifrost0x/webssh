package smb

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Component rules of app/smb_paths.py.
const (
	// maxComponents bounds the handles and round trips one path needs
	// (SMB_PATH_MAX_COMPONENTS).
	maxComponents = 128
	maxComponent  = 255
	maxShareName  = 80
	maxPathLength = 4096
)

var (
	errInvalidPath = errors.New("smb: invalid path")
	reservedDevice = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$`)
)

const invalidInComponent = `<>:"/\|?*`

// validComponent is _validate_component: 1 to maximum characters, not "."
// or "..", no trailing dot or space, no control character, none of
// <>:"/\|?* and no reserved device name. A dollar sign is allowed in path
// components and refused in share names (administrative shares).
func validComponent(v string, maximum int, allowDollar bool) bool {
	if v == "" || !utf8.ValidString(v) || utf8.RuneCountInString(v) > maximum || v == "." || v == ".." ||
		strings.HasSuffix(v, ".") || strings.HasSuffix(v, " ") {
		return false
	}
	for _, c := range v {
		if c < 32 || strings.ContainsRune(invalidInComponent, c) || (c == '$' && !allowDollar) {
			return false
		}
	}
	return !reservedDevice.MatchString(v)
}

// ValidShareName is SMBShareName.parse: one component of at most 80
// characters without a dollar sign.
func ValidShareName(v string) bool { return validComponent(v, maxShareName, false) }

// splitPath turns a canonical share path ("/" or "/a/b") into its
// components, checked with the rules of SMBPath.parse. The root has none.
func splitPath(p string) ([]string, error) {
	if p == "/" {
		return nil, nil
	}
	if !strings.HasPrefix(p, "/") || utf8.RuneCountInString(p) > maxPathLength || strings.HasSuffix(p, "/") || strings.Contains(p, "//") {
		return nil, errInvalidPath
	}
	parts := strings.Split(p[1:], "/")
	if len(parts) > maxComponents {
		return nil, errInvalidPath
	}
	for _, part := range parts {
		if !validComponent(part, maxComponent, true) {
			return nil, errInvalidPath
		}
	}
	return parts, nil
}

// joinPath is the canonical share path of components.
func joinPath(parts []string) string { return "/" + strings.Join(parts, "/") }

// smbPath joins components with the SMB separator, relative to the share.
func smbPath(parts []string) string { return strings.Join(parts, `\`) }

// child appends one component after checking it.
func child(parts []string, name string) ([]string, error) {
	if !validComponent(name, maxComponent, true) || len(parts)+1 > maxComponents {
		return nil, errInvalidPath
	}
	return append(append(make([]string, 0, len(parts)+1), parts...), name), nil
}

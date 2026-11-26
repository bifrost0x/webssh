package auth

import (
	"net/url"
	"strings"
)

// SafeContinuation is safe_continuation: only a local absolute path
// (with query, without fragment) of at most 512 characters survives;
// everything else becomes "/". The raw value is checked first, because a
// browser strips leading whitespace and resolves "//host" and "/\host" as
// another host.
func SafeContinuation(v string) string {
	if v == "" || len([]rune(v)) > 512 || strings.ContainsRune(v, '\\') {
		return "/"
	}
	for _, r := range v {
		if r < 0x20 {
			return "/"
		}
	}
	if !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") {
		return "/"
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "" || u.Host != "" || u.Fragment != "" || strings.Contains(v, "#") ||
		!strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return v
}

// PublicContinuation is public_continuation: the safe continuation with
// the application root added once. A path with a dot segment (also
// percent-encoded) goes to the root.
func PublicContinuation(root, v string) string {
	c := SafeContinuation(v)
	prefix := strings.TrimRight(root, "/")
	path := c
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	for seg := range strings.SplitSeq(path, "/") {
		s := strings.ReplaceAll(strings.ToLower(seg), "%2e", ".")
		if s == "." || s == ".." {
			return prefix + "/"
		}
	}
	if prefix == "" || path == prefix || strings.HasPrefix(path, prefix+"/") {
		return c
	}
	return prefix + c
}

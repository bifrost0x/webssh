package github

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"
)

// Limits and patterns of app/github_auth_service.py.
const (
	maxOrgs        = 50
	maxRedirectLen = 2048
	minSecretChars = 20
	maxSecretChars = 512
)

var (
	clientIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
	orgPattern      = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
)

// errConfig is a refused configuration (GitHubConfigurationError). Its
// text never reaches the browser of an update, which gets "Invalid GitHub
// configuration"; the stored configuration shows it as its error.
type errConfig struct{ msg string }

func (e *errConfig) Error() string { return e.msg }

func configErr(msg string) error { return &errConfig{msg: msg} }

// Configuration texts of the Python release, shown as "error" in the
// administration.
const (
	msgOrgPolicyInvalid = "Stored organization policy is invalid."
	msgClientIDInvalid  = "GitHub client ID is missing or invalid."
	msgSecretMissing    = "GitHub client secret is missing." // #nosec G101 -- a message, not a credential
	msgRedirectExact    = "redirect_uri must be the exact HTTPS URL for /auth/github/callback"
	msgRedirectInvalid  = "redirect_uri is invalid"
	msgRedirectTooLong  = "redirect_uri is too long"
)

// normalizeOrgs is _normalize_orgs for a decoded JSON value: a string is
// split at commas, a list must hold strings; names are stripped,
// lower-cased, checked, de-duplicated in order and at most 50.
func normalizeOrgs(v any) ([]string, error) {
	var values []any
	switch t := v.(type) {
	case string:
		for part := range strings.SplitSeq(t, ",") {
			values = append(values, part)
		}
	case []any:
		values = t
	default:
		return nil, configErr("allowed_orgs must be a list")
	}
	out := []string{}
	for _, raw := range values {
		s, ok := raw.(string)
		if !ok {
			return nil, configErr("allowed_orgs must contain only organization names")
		}
		org := pyLower(pyStrip(s))
		if org == "" {
			continue
		}
		if !orgPattern.MatchString(org) {
			return nil, configErr("allowed_orgs contains an invalid organization")
		}
		if !slices.Contains(out, org) {
			out = append(out, org)
		}
	}
	if len(out) > maxOrgs {
		return nil, configErr("allowed_orgs contains too many organizations")
	}
	return out, nil
}

// decodeJSON decodes a JSON text the way json.loads accepts it for the
// values these settings use (a repeated member: the last one wins).
func decodeJSON(text []byte, v any) error {
	return json.Unmarshal(text, v, jsontext.AllowDuplicateNames(true), jsontext.AllowInvalidUTF8(true))
}

// storedOrgs reads allowed_orgs_json as get_settings does.
func storedOrgs(text string) ([]string, error) {
	if text == "" {
		text = "[]"
	}
	var v any
	if err := decodeJSON([]byte(text), &v); err != nil {
		return nil, configErr(msgOrgPolicyInvalid)
	}
	orgs, err := normalizeOrgs(v)
	if err != nil {
		return nil, configErr(msgOrgPolicyInvalid)
	}
	return orgs, nil
}

// encodeOrgs is json.dumps(orgs, separators=(',', ':')); the names are
// ASCII after normalizeOrgs.
func encodeOrgs(orgs []string) string {
	b, _ := json.Marshal(orgs)
	return string(b)
}

// validateRedirect is _validate_redirect_uri; root is APPLICATION_ROOT.
func validateRedirect(uri, root string) error {
	uri = pyStrip(uri)
	u, err := pysplit(uri)
	if err == nil {
		err = u.checkPort()
	}
	if err != nil {
		return configErr(msgRedirectInvalid)
	}
	host := u.hostname()
	loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	user, _ := u.userinfo()
	if host == "" || user || u.path != strings.TrimRight(root, "/")+"/auth/github/callback" ||
		u.query != "" || u.fragment != "" || !(u.scheme == "https" || u.scheme == "http" && loopback) {
		return configErr(msgRedirectExact)
	}
	if utf8.RuneCountInString(uri) > maxRedirectLen {
		return configErr(msgRedirectTooLong)
	}
	return nil
}

// validSecret is the rule for a new client secret: 20 to 512 characters
// on one line.
func validSecret(s string) bool {
	n := utf8.RuneCountInString(s)
	return n >= minSecretChars && n <= maxSecretChars && !strings.ContainsAny(s, "\r\n")
}

// errorText returns the message of a configuration error, or "".
func errorText(err error) string {
	if ce, ok := errors.AsType[*errConfig](err); ok {
		return ce.msg
	}
	if err != nil {
		return err.Error()
	}
	return ""
}

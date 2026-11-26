package httpapi

import (
	"encoding/json"
	"fmt"
	"html/template"
	"slices"
	"strings"
	"unicode/utf8"
)

// view is what the page templates execute against: the page data plus the
// helpers that need the asset index. Derived values that the Python
// templates computed inline with set statements are methods here.
type view struct {
	*PageData
	assets *Assets
}

// pageFuncs are the template functions. They take plain values and return
// plain values; none of them returns template.HTML, so every result is
// escaped for its context.
var pageFuncs = template.FuncMap{
	"has":       slices.Contains[[]string],
	"initial":   initial,
	"json":      toJSON,
	"methodKey": methodKey,
}

// Asset returns the versioned URL of a file below static/, like
// static_asset_url. An unknown file fails the render, so a page never
// points at a missing script.
func (v view) Asset(name string) (string, error) {
	version, ok := v.assets.Version(name)
	if !ok {
		return "", fmt.Errorf("static asset does not exist: %s", name)
	}
	return v.BasePath + "/static/" + name + "?v=" + version, nil
}

// URL returns an application path below the base path.
func (v view) URL(path string) string {
	return v.BasePath + path
}

// logo is the argument of the brand_logo template.
type logo struct {
	Class      string
	Decorative bool
	Href       string
}

// Logo prepares the brand logo for a CSS class.
func (v view) Logo(class string, decorative bool) (logo, error) {
	href, err := v.Asset("images/webssh-logo.svg")
	return logo{Class: class, Decorative: decorative, Href: href}, err
}

// alert is one rendered authentication message.
type alert struct {
	Category, Message, Key string
}

// Alert prepares one authentication message with its translation key.
func (v view) Alert(message, category string) alert {
	return alert{Category: category, Message: message, Key: flashMessageKeys[message]}
}

// AuthMessages are the queued messages shown on the sign-in pages; data
// categories are not shown.
func (v view) AuthMessages() []alert {
	var out []alert
	for _, f := range v.Flashes {
		if !slices.Contains(flashDataCategories, f.Category) {
			out = append(out, v.Alert(f.Message, f.Category))
		}
	}
	return out
}

// flashedMessages is the flash payload of the workspace page.
type flashedMessages struct {
	Keys     map[string]string `json:"keys"`
	Messages [][2]string       `json:"messages"`
}

// FlashedMessages are the queued messages for the workspace page's
// script. As in Python, only the login_username category is left out.
func (v view) FlashedMessages() flashedMessages {
	out := flashedMessages{Keys: flashMessageKeys, Messages: [][2]string{}}
	for _, f := range v.Flashes {
		if f.Category != "login_username" {
			out.Messages = append(out.Messages, [2]string{f.Category, f.Message})
		}
	}
	return out
}

// lastFlash returns the last message of a category, trimmed.
func (v view) lastFlash(category string) string {
	last := ""
	for _, f := range v.Flashes {
		if f.Category == category {
			last = f.Message
		}
	}
	return strings.TrimSpace(last)
}

// LocalUsernameHint is the username to prefill after a failed local
// sign-in.
func (v view) LocalUsernameHint() string {
	if v.lastFlash("login_auth_source") == "local" {
		return v.lastFlash("login_username")
	}
	return ""
}

// LDAPUsernameHint is the username to prefill after a failed directory
// sign-in.
func (v view) LDAPUsernameHint() string {
	if v.LDAPEnabled && v.lastFlash("login_auth_source") == "ldap" {
		return v.lastFlash("login_username")
	}
	return ""
}

// SelectedAuthSource is the sign-in form shown first.
func (v view) SelectedAuthSource() string {
	switch {
	case v.AuthSource == "local" || v.AuthSource == "ldap":
		return v.AuthSource
	case v.LocalUsernameHint() != "":
		return "local"
	case v.LDAPUsernameHint() != "":
		return "ldap"
	case v.LDAPEnabled:
		return "ldap"
	}
	return "local"
}

// DefaultMFAMethod is the second factor offered first; empty without a
// pending second step.
func (v view) DefaultMFAMethod() string {
	switch {
	case !v.MFARequired:
		return ""
	case slices.Contains(v.MFAMethods, "totp"):
		return "totp"
	case slices.Contains(v.MFAMethods, "passkey"):
		return "passkey"
	}
	return "recovery"
}

// PrimaryMethod is the first method of the current sign-in.
func (v view) PrimaryMethod() AuthMethod {
	if len(v.AuthenticationMethods) == 0 {
		return AuthMethod{}
	}
	return v.AuthenticationMethods[0]
}

// TranslationAssets maps each language to the versioned URL of its file
// in static/js/i18n/.
func (v view) TranslationAssets() (map[string]string, error) {
	out := map[string]string{}
	for _, name := range v.assets.Translations() {
		url, err := v.Asset("js/i18n/" + name + ".js")
		if err != nil {
			return nil, err
		}
		out[name] = url
	}
	return out, nil
}

// PlatformAssets maps each known host platform to its icon URL.
func (v view) PlatformAssets() (map[string]string, error) {
	out := make(map[string]string, len(hostPlatforms))
	for _, p := range hostPlatforms {
		url, err := v.Asset("icons/platforms/" + p + ".svg")
		if err != nil {
			return nil, err
		}
		out[p] = url
	}
	return out, nil
}

// TerminalAppearanceJSON is the saved terminal appearance as JSON text
// for a data attribute; html/template escapes it there.
func (v view) TerminalAppearanceJSON() (string, error) {
	if v.TerminalAppearance == nil {
		return "{}", nil
	}
	return toJSON(v.TerminalAppearance)
}

// OverviewPreferencesValue applies the Python default.
func (v view) OverviewPreferencesValue() OverviewPreferences {
	if v.OverviewPreferences == nil {
		return OverviewPreferences{Dismissed: []string{}}
	}
	return *v.OverviewPreferences
}

// runtimeLimits is the limits payload of the workspace page.
type runtimeLimits struct {
	Transfer TransferLimits `json:"transfer"`
	SSHInput SSHInputLimits `json:"sshInput"`
}

// RuntimeLimits are the limits the workspace scripts enforce up front.
func (v view) RuntimeLimits() runtimeLimits {
	return runtimeLimits{Transfer: v.TransferLimits, SSHInput: v.SSHInputLimits}
}

// toJSON encodes a value for an attribute. The text is escaped by
// html/template afterwards; json.Marshal also escapes <, > and &.
func toJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	return string(data), err
}

// initial is the upper-cased first character of a name, as Python's
// name[:1]|upper.
func initial(name string) string {
	if name == "" {
		return ""
	}
	_, size := utf8.DecodeRuneInString(name)
	return strings.ToUpper(name[:size])
}

// methodKey returns the translation key of a sign-in method, or the key
// for an unknown method. Only keys from this list reach the page.
func methodKey(key string) string {
	if slices.Contains(authMethodKeys, key) {
		return key
	}
	return "security.methodUnknown"
}

package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

func TestAssetVersionIsContentHash(t *testing.T) {
	files := fstest.MapFS{
		"js/app.js":      {Data: []byte("console.log(1)\n")},
		"js/i18n/de.js":  {Data: []byte("de")},
		"js/i18n/en.js":  {Data: []byte("en")},
		"js/i18n/x/y.js": {Data: []byte("nested")},
	}
	a, err := NewAssets(files)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("console.log(1)\n"))
	want := hex.EncodeToString(sum[:])[:16]
	if got, ok := a.Version("js/app.js"); !ok || got != want {
		t.Fatalf("Version = %q, %v; want %q", got, ok, want)
	}
	if _, ok := a.Version("js/missing.js"); ok {
		t.Fatal("Version reports a missing file")
	}
	if got := strings.Join(a.Translations(), ","); got != "de,en" {
		t.Fatalf("Translations = %q, want de,en (direct children only)", got)
	}
	v := view{PageData: &PageData{BasePath: "/root"}, assets: a}
	url, err := v.Asset("js/app.js")
	if err != nil || url != "/root/static/js/app.js?v="+want {
		t.Fatalf("Asset = %q, %v", url, err)
	}
	if _, err := v.Asset("../secret"); err == nil {
		t.Fatal("Asset accepted a path outside the index")
	}
}

func TestNewAssetsRejectsEmptyTree(t *testing.T) {
	if _, err := NewAssets(fstest.MapFS{}); !errors.Is(err, errNoAssets) {
		t.Fatalf("err = %v, want errNoAssets", err)
	}
}

func TestStaticAssetsMatchStagedCopy(t *testing.T) {
	a, err := StaticAssets()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Version("css/style.css"); !ok {
		t.Fatal("embedded assets lack css/style.css; stage static/ first")
	}
	if _, err := fs.Stat(a.FS(), "js/app.js"); err != nil {
		t.Fatalf("FS: %v", err)
	}
}

func TestNewRendererFailsOnMissingAsset(t *testing.T) {
	a, err := NewAssets(fstest.MapFS{"css/style.css": {Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewRenderer(a); err == nil || !strings.Contains(err.Error(), "static asset does not exist") {
		t.Fatalf("NewRenderer err = %v, want a missing asset error", err)
	}
}

func TestRenderUnknownPageWritesNothing(t *testing.T) {
	r := testRenderer(t)
	var buf bytes.Buffer
	if err := r.Render(&buf, Page("admin"), PageData{}); err == nil {
		t.Fatal("Render accepted an unknown page")
	}
	if buf.Len() != 0 {
		t.Fatal("Render wrote output for an unknown page")
	}
}

var (
	scriptTag  = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)
	startTag   = regexp.MustCompile(`<[a-zA-Z][\w-]*((?:\s+[^\s"'>/=]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+))?)*)\s*/?>`)
	attribute  = regexp.MustCompile(`([^\s"'>/=]+)(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s"'>]+))?`)
	scriptType = regexp.MustCompile(`\btype="application/json"`)
	scriptSrc  = regexp.MustCompile(`\bsrc="[^"]+"`)
)

// policyProblems reports what the content security policy (script-src
// 'self', no nonces) would block or what would bypass it: every script
// must be a file from this origin or an inert JSON block, and no element
// may carry an inline event handler.
func policyProblems(page []byte) []string {
	var problems []string
	for _, m := range scriptTag.FindAllSubmatch(page, -1) {
		attrs, body := m[1], m[2]
		switch {
		case scriptType.Match(attrs):
		case scriptSrc.Match(attrs) && len(bytes.TrimSpace(body)) == 0:
		default:
			problems = append(problems, fmt.Sprintf("inline script %q", m[0][:min(len(m[0]), 120)]))
		}
	}
	for _, tag := range startTag.FindAllSubmatch(page, -1) {
		for _, attr := range attribute.FindAllSubmatch(tag[1], -1) {
			if bytes.HasPrefix(bytes.ToLower(attr[1]), []byte("on")) {
				problems = append(problems, fmt.Sprintf("inline event handler in %q", tag[0][:min(len(tag[0]), 120)]))
			}
		}
	}
	if bytes.Contains(page, []byte("vendor/socketio/")) {
		problems = append(problems, "loads the Socket.IO client")
	}
	return problems
}

func checkPolicy(t *testing.T, name string, page []byte) {
	t.Helper()
	for _, p := range policyProblems(page) {
		t.Errorf("%s: %s", name, p)
	}
}

func TestPolicyProblemsDetects(t *testing.T) {
	for _, bad := range []string{
		`<script>alert(1)</script>`,
		`<script src="/a.js">alert(1)</script>`,
		`<div class="x" onclick="alert(1)">`,
		`<img src=x ONERROR=alert(1)>`,
		`<script src="/static/vendor/socketio/socket.io.min.js"></script>`,
	} {
		if len(policyProblems([]byte(bad))) == 0 {
			t.Errorf("policyProblems missed %q", bad)
		}
	}
	for _, good := range []string{
		`<script src="/a.js"></script><script type="application/json" id="x">{"a":"<b>"}</script>`,
		`<meta content="&#34; onload=&#34;x" name="a"><button data-only="1" type="button">`,
	} {
		if p := policyProblems([]byte(good)); len(p) != 0 {
			t.Errorf("policyProblems(%q) = %v", good, p)
		}
	}
}

func TestPagesHaveNoInlineScripts(t *testing.T) {
	r := testRenderer(t)
	for _, c := range loadCases(t) {
		checkPolicy(t, c.Name, renderCase(t, r, c))
	}
}

func TestUserValuesAreEscaped(t *testing.T) {
	r := testRenderer(t)
	for _, c := range loadCases(t) {
		if !strings.HasSuffix(c.Name, "_escaping") {
			continue
		}
		page := string(renderCase(t, r, c))
		for _, raw := range []string{"<script>alert(", "</script><script>", `" onload="`, `" onclick="`, "<b>label</b>"} {
			if strings.Contains(page, raw) {
				t.Errorf("%s: unescaped %q in the page", c.Name, raw)
			}
		}
	}
}

// FuzzUserValues renders the workspace and settings pages with arbitrary
// user-controlled values; none may add a script element or an event
// handler.
func FuzzUserValues(f *testing.F) {
	for _, s := range []string{"alice", "<script>alert(1)</script>", `"><img src=x onerror=alert(1)>`, "</script><!--", " ", "javascript:alert(1)"} {
		f.Add(s, s)
	}
	r, err := NewRenderer(testAssets(&testing.T{}))
	if err != nil {
		f.Fatal(err)
	}
	baseline := map[Page]int{}
	for _, p := range []Page{PageWorkspace, PageSettings, PageLogin} {
		var buf bytes.Buffer
		if err := r.Render(&buf, p, fuzzData("a", "b")); err != nil {
			f.Fatal(err)
		}
		baseline[p] = len(scriptTag.FindAll(buf.Bytes(), -1))
	}
	f.Fuzz(func(t *testing.T, name, text string) {
		for p, scripts := range baseline {
			var buf bytes.Buffer
			if err := r.Render(&buf, p, fuzzData(name, text)); err != nil {
				t.Fatal(err)
			}
			if got := len(scriptTag.FindAll(buf.Bytes(), -1)); got != scripts {
				t.Fatalf("%s: %d scripts, want %d", p, got, scripts)
			}
			checkPolicy(t, string(p), buf.Bytes())
		}
	})
}

func fuzzData(name, text string) PageData {
	return PageData{
		User:                    User{ID: 1, Username: name, IsAdmin: true, Authenticated: true},
		CSRFToken:               text,
		BackgroundScope:         text,
		Theme:                   text,
		AdminPanelEnabled:       true,
		LDAPEnabled:             true,
		LDAPProviderID:          text,
		LDAPError:               text,
		Flashes:                 []Flash{{Category: text, Message: name}},
		AuthenticationMethods:   []AuthMethod{{ID: text, Label: name, I18nKey: text}},
		TerminalAppearance:      map[string]any{text: name},
		InitialInventory:        map[string]any{"profiles": []any{map[string]any{"name": name}}},
		DisconnectSessionAction: text,
	}
}

// TestNoTrustedTemplateTypes keeps template.HTML and its relatives out of
// the page code: every value is escaped for its context.
func TestNoTrustedTemplateTypes(t *testing.T) {
	trusted := map[string]bool{"HTML": true, "HTMLAttr": true, "JS": true, "JSStr": true, "CSS": true, "URL": true, "Srcset": true}
	names, err := filepath.Glob("page*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if ok && trusted[sel.Sel.Name] {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "template" {
					t.Errorf("%s uses template.%s", name, sel.Sel.Name)
				}
			}
			return true
		})
	}
}

func TestDerivedSignInValues(t *testing.T) {
	flashes := func(user, source string) []Flash {
		return []Flash{{"login_username", " " + user + " "}, {"login_auth_source", source}}
	}
	tests := []struct {
		name                 string
		data                 PageData
		source, mfa, l, ldap string
	}{
		{"default local", PageData{}, "local", "", "", ""},
		{"default ldap", PageData{LDAPEnabled: true}, "ldap", "", "", ""},
		{"explicit source wins", PageData{AuthSource: "local", LDAPEnabled: true, Flashes: flashes("bob", "ldap")}, "local", "", "", "bob"},
		{"unknown source ignored", PageData{AuthSource: "oidc"}, "local", "", "", ""},
		{"local hint", PageData{LDAPEnabled: true, Flashes: flashes("amy", "local")}, "local", "", "amy", ""},
		{"ldap hint needs ldap", PageData{Flashes: flashes("amy", "ldap")}, "local", "", "", ""},
		{"ldap hint", PageData{LDAPEnabled: true, Flashes: flashes("amy", "ldap")}, "ldap", "", "", "amy"},
		{"mfa totp first", PageData{MFARequired: true, MFAMethods: []string{"recovery", "passkey", "totp"}}, "local", "totp", "", ""},
		{"mfa passkey", PageData{MFARequired: true, MFAMethods: []string{"recovery", "passkey"}}, "local", "passkey", "", ""},
		{"mfa recovery", PageData{MFARequired: true}, "local", "recovery", "", ""},
		{"methods without mfa", PageData{MFAMethods: []string{"totp"}}, "local", "", "", ""},
	}
	for _, tt := range tests {
		v := view{PageData: &tt.data}
		if got := v.SelectedAuthSource(); got != tt.source {
			t.Errorf("%s: SelectedAuthSource = %q, want %q", tt.name, got, tt.source)
		}
		if got := v.DefaultMFAMethod(); got != tt.mfa {
			t.Errorf("%s: DefaultMFAMethod = %q, want %q", tt.name, got, tt.mfa)
		}
		if got := v.LocalUsernameHint(); got != tt.l {
			t.Errorf("%s: LocalUsernameHint = %q, want %q", tt.name, got, tt.l)
		}
		if got := v.LDAPUsernameHint(); got != tt.ldap {
			t.Errorf("%s: LDAPUsernameHint = %q, want %q", tt.name, got, tt.ldap)
		}
	}
}

func TestHelpers(t *testing.T) {
	for in, want := range map[string]string{"": "", "alice": "A", "émile": "É", "_x": "_", "\xff": "\uFFFD"} {
		if got := initial(in); got != want {
			t.Errorf("initial(%q) = %q, want %q", in, got, want)
		}
	}
	if methodKey("security.methodTotp") != "security.methodTotp" || methodKey(`" onclick="x`) != "security.methodUnknown" {
		t.Error("methodKey does not limit keys to the known list")
	}
	v := view{PageData: &PageData{Flashes: []Flash{{"login_username", "a"}, {"login_auth_source", "local"}, {"error", "Invalid username or password"}, {"info", "other"}}}}
	msgs := v.AuthMessages()
	if len(msgs) != 2 || msgs[0].Key != "auth.invalidCredentials" || msgs[1].Key != "" {
		t.Errorf("AuthMessages = %+v", msgs)
	}
	fm := v.FlashedMessages()
	if len(fm.Messages) != 3 || fm.Messages[0][0] != "login_auth_source" {
		t.Errorf("FlashedMessages = %+v, want login_username dropped only", fm.Messages)
	}
	if got := (view{PageData: &PageData{}}).PrimaryMethod(); got != (AuthMethod{}) {
		t.Errorf("PrimaryMethod of no methods = %+v", got)
	}
}

package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// websocketModule is the WebSocket library of internal/realtime (K6).
const websocketModule = "github.com/coder/websocket"

// websocketAcceptFile is the one file that configures the library: it
// turns its origin check off (OriginPolicy decides before Accept) and
// keeps compression off.
const websocketAcceptFile = "internal/realtime/server.go"

// guardedWebsocketFields may be set only in websocketAcceptFile.
// InsecureSkipVerify turns off the library's origin check, CompressionMode
// could turn on compression (K6 conditions).
var guardedWebsocketFields = []string{"InsecureSkipVerify", "CompressionMode", "OriginPatterns"}

// websocketViolations reports uses of the guarded fields outside the
// accept file, in a file that imports the library or belongs to
// internal/realtime (which can change the options acceptOptions returns
// without importing the library). Test files are included: a test that
// switches the origin check off elsewhere would test another
// configuration than the one that runs.
func websocketViolations(rel string, src []byte) ([]string, error) {
	f, err := parser.ParseFile(token.NewFileSet(), rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	imported := false
	for _, spec := range f.Imports {
		if p, err := strconv.Unquote(spec.Path.Value); err == nil && p == websocketModule {
			imported = true
		}
	}
	if path.Dir(rel) == path.Dir(websocketAcceptFile) {
		imported = true
	}
	if !imported || rel == websocketAcceptFile {
		return nil, nil
	}
	var problems []string
	ast.Inspect(f, func(n ast.Node) bool {
		var name string
		switch x := n.(type) {
		case *ast.KeyValueExpr:
			if id, ok := x.Key.(*ast.Ident); ok {
				name = id.Name
			}
		case *ast.SelectorExpr:
			name = x.Sel.Name
		}
		if slices.Contains(guardedWebsocketFields, name) {
			problems = append(problems, rel+": sets "+name+" of "+websocketModule+"; only "+websocketAcceptFile+" configures the library")
		}
		return true
	})
	return problems, nil
}

func TestWebsocketConfiguredInOneFile(t *testing.T) {
	root := moduleRoot(t)
	found := walkRepo(t, root)
	var problems []string
	for _, rel := range found.goFiles {
		p, err := websocketViolations(rel, readRepoFile(t, root, rel))
		if err != nil {
			t.Fatal(err)
		}
		problems = append(problems, p...)
	}
	for _, p := range problems {
		t.Error(p)
	}
	// The accept file still sets the fields the conditions require.
	src := readRepoFile(t, root, websocketAcceptFile)
	f, err := parser.ParseFile(token.NewFileSet(), filepath.Base(websocketAcceptFile), src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.KeyValueExpr:
			if id, ok := x.Key.(*ast.Ident); ok {
				if sel, ok := x.Value.(*ast.SelectorExpr); ok {
					seen[id.Name] = sel.Sel.Name
				} else if v, ok := x.Value.(*ast.Ident); ok {
					seen[id.Name] = v.Name
				}
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "SetReadLimit" {
				seen["SetReadLimit"] = "called"
			}
		}
		return true
	})
	for field, want := range map[string]string{
		"InsecureSkipVerify": "true", "CompressionMode": "CompressionDisabled", "SetReadLimit": "called",
	} {
		if seen[field] != want {
			t.Errorf("%s: %s is %q, want %q", websocketAcceptFile, field, seen[field], want)
		}
	}
}

func TestWebsocketViolations(t *testing.T) {
	cases := []struct {
		name, file, src string
		want            int
	}{
		{"accept file", websocketAcceptFile, `package realtime
import "github.com/coder/websocket"
var o = websocket.AcceptOptions{InsecureSkipVerify: true}`, 0},
		{"other file", "internal/realtime/conn.go", `package realtime
import "github.com/coder/websocket"
var o = websocket.AcceptOptions{InsecureSkipVerify: true}`, 1},
		{"field assignment", "internal/realtime/x_test.go", `package realtime
import ws "github.com/coder/websocket"
func f(o *ws.AcceptOptions) { o.CompressionMode = ws.CompressionContextTakeover; o.OriginPatterns = nil }`, 2},
		{"options changed without the import", "internal/realtime/hello.go", `package realtime
func f() { o := acceptOptions(nil); o.OriginPatterns = []string{"*"} }`, 1},
		{"tls config elsewhere", "internal/auth/ldap/dial.go", `package ldap
import "crypto/tls"
var c = tls.Config{InsecureSkipVerify: false}`, 0},
	}
	for _, tt := range cases {
		got, err := websocketViolations(tt.file, []byte(tt.src))
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != tt.want {
			t.Errorf("%s: %d problems %v, want %d", tt.name, len(got), got, tt.want)
		}
	}
}

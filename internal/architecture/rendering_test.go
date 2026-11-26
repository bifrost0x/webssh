package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// errorTextExceptions lists files that may turn an error text into a safe
// message, with the reason a reviewer checked.
var errorTextExceptions = map[string]string{
	// Validate errors are messages written by our own request types.
	"internal/realtime/protocol/route.go": "Validator messages are safe by contract",
}

// TestErrorTextIsNeverRendered keeps the text of errors away from users.
// Error() of a *fault.Error or a dialer error contains causes with
// remote-supplied text (server messages, proxy replies, paths); only
// fault.Status may produce what a client sees. So Error() must not feed
// the message of fault.New or fault.Wrap, and transport files of
// capabilities (http.go, http_*.go, realtime.go) must not call it at all.
func TestErrorTextIsNeverRendered(t *testing.T) {
	root := moduleRoot(t)
	var problems []string
	for _, top := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || errorTextExceptions[rel] != "" {
				return nil
			}
			problems = append(problems, errorTextUses(t, p, rel)...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range problems {
		t.Error(p)
	}
}

func isCapabilityTransport(rel string) bool {
	if !strings.HasPrefix(rel, "internal/") || strings.HasPrefix(rel, "internal/httpapi/") || strings.HasPrefix(rel, "internal/realtime/") {
		return false
	}
	base := path.Base(rel)
	return base == "http.go" || strings.HasPrefix(base, "http_") || base == "realtime.go"
}

func errorTextUses(t *testing.T, file, rel string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	var problems []string
	isErrorCall := func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 0 {
			return false
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		return ok && sel.Sel.Name == "Error"
	}
	transport := isCapabilityTransport(rel)
	ast.Inspect(f, func(n ast.Node) bool {
		if transport && isErrorCall(n) {
			problems = append(problems, fset.Position(n.Pos()).String()+": transport file calls Error(); use fault.Status")
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "New" && sel.Sel.Name != "Wrap") {
			return true
		}
		if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "fault" {
			return true
		}
		for _, arg := range call.Args {
			ast.Inspect(arg, func(m ast.Node) bool {
				if isErrorCall(m) {
					problems = append(problems, fset.Position(m.Pos()).String()+": error text used as a fault message")
				}
				return true
			})
		}
		return true
	})
	return problems
}

func TestErrorTextRule(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]struct {
		rel, src string
		want     int
	}{
		"message from error":   {"internal/x/service.go", "package x\nfunc f(err error) error { return fault.Wrap(fault.Internal, err, err.Error()) }\n", 1},
		"message nested":       {"internal/x/service.go", "package x\nfunc f(err error) error { return fault.New(fault.Internal, \"x: \"+err.Error()) }\n", 1},
		"cause only":           {"internal/x/service.go", "package x\nfunc f(err error) error { return fault.Wrap(fault.Internal, err, \"\") }\n", 0},
		"transport renders":    {"internal/x/http.go", "package x\nfunc f(w W, err error) { w.Write([]byte(err.Error())) }\n", 1},
		"service may log text": {"internal/x/service.go", "package x\nfunc f(err error) string { return err.Error() }\n", 0},
		"edge is out of scope": {"internal/httpapi/http.go", "package x\nfunc f(err error) string { return err.Error() }\n", 0},
	}
	for name, c := range cases {
		file := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".go")
		if err := os.WriteFile(file, []byte(c.src), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := errorTextUses(t, file, c.rel); len(got) != c.want {
			t.Errorf("%s: %v", name, got)
		}
	}
}

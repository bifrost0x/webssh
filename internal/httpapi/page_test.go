package httpapi

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"testing/fstest"
)

var (
	testAssetsOnce sync.Once
	testAssetsVal  *Assets
	testAssetsErr  error
)

// testAssets indexes the staged static/ once for all tests.
func testAssets(t testing.TB) *Assets {
	t.Helper()
	testAssetsOnce.Do(func() {
		static, err := StaticAssets()
		if err != nil {
			testAssetsErr = err
			return
		}
		staged := static.FS()
		files := fstest.MapFS{}
		err = fs.WalkDir(staged, ".", func(name string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, err := fs.ReadFile(staged, name)
			files[name] = &fstest.MapFile{Data: data}
			return err
		})
		if err != nil {
			testAssetsErr = err
			return
		}
		testAssetsVal, testAssetsErr = NewAssets(files)
	})
	if testAssetsErr != nil {
		t.Fatalf("test assets: %v", testAssetsErr)
	}
	return testAssetsVal
}

func testRenderer(t *testing.T) *Renderer {
	t.Helper()
	r, err := NewRenderer(testAssets(t))
	if err != nil {
		t.Fatalf("NewRenderer: %v", err)
	}
	return r
}

type pageCase struct {
	Name string          `json:"name"`
	Page Page            `json:"page"`
	Vars json.RawMessage `json:"vars"`
}

func loadCases(t *testing.T) []pageCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "pages", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Cases []pageCase }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func renderCase(t *testing.T, r *Renderer, c pageCase) []byte {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(c.Vars))
	dec.DisallowUnknownFields()
	var data PageData
	if err := dec.Decode(&data); err != nil {
		t.Fatalf("%s: decode vars: %v", c.Name, err)
	}
	var buf bytes.Buffer
	if err := r.Render(&buf, c.Page, data); err != nil {
		t.Fatalf("%s: %v", c.Name, err)
	}
	return buf.Bytes()
}

// assetVersion matches the content version of asset URLs. The parity
// output holds a placeholder, so the comparison does not depend on the
// static files; TestAssetVersionIsContentHash checks the version itself.
var assetVersion = regexp.MustCompile(`\?v=[0-9a-f]{16}`)

func maskVersions(page []byte) []byte {
	return assetVersion.ReplaceAll(page, []byte("?v=VERSION"))
}

// parityDirEnv names the directory the parity job collects the rendered
// cases in. tests/test_go_page_parity.py renders the same cases with the
// Jinja templates and compares both.
const parityDirEnv = "WEBSSH_PAGE_PARITY_DIR"

// TestPagesRenderCases renders every parity case and, in the parity job,
// writes the pages for the Python side.
func TestPagesRenderCases(t *testing.T) {
	r := testRenderer(t)
	dir := os.Getenv(parityDirEnv)
	for _, c := range loadCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			page := maskVersions(renderCase(t, r, c))
			if dir == "" {
				return
			}
			if err := os.WriteFile(filepath.Join(dir, c.Name+".html"), page, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

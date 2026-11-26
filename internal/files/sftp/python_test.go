package sftp

import (
	"compress/gzip"
	"encoding/base64"
	json "encoding/json/v2"
	"maps"
	"os"
	"testing"
)

// testdata/python_vectors.json.gz is produced by testdata/python_vectors.py
// from the Python release: the decisions of its SFTP metadata checks.
type pyVectors struct {
	Limits struct {
		MaxName     int `json:"max_name"`
		MaxMetadata int `json:"max_metadata"`
		MaxHandle   int `json:"max_handle"`
	} `json:"limits"`
	Vectors struct {
		Attrs []struct {
			B64    string `json:"b64"`
			Accept bool   `json:"accept"`
		} `json:"attrs"`
		Names []struct {
			B64     string `json:"b64"`
			Accept  bool   `json:"accept"`
			Listing bool   `json:"listing"`
		} `json:"names"`
		Version []struct {
			B64    string `json:"b64"`
			Result *struct {
				Version    uint32            `json:"version"`
				Extensions map[string]string `json:"extensions"`
			} `json:"result"`
		} `json:"version"`
		EntryNames []struct {
			Name string `json:"name"`
			Safe bool   `json:"safe"`
		} `json:"entry_names"`
	} `json:"vectors"`
}

func loadPython(t *testing.T) (pyVectors, limits) {
	t.Helper()
	f, err := os.Open("testdata/python_vectors.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var v pyVectors
	if err := json.UnmarshalRead(zr, &v); err != nil {
		t.Fatal(err)
	}
	l := limits{maxName: v.Limits.MaxName, maxHandle: v.Limits.MaxHandle, maxMetadata: v.Limits.MaxMetadata}
	if l != testLimits {
		t.Fatalf("vectors were made with other limits: %+v", l)
	}
	return v, l
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPythonAttributeRules(t *testing.T) {
	v, l := loadPython(t)
	for i, c := range v.Vectors.Attrs {
		got := validateReply(fxpAttrs, b64(t, c.B64), l) == nil
		if got != c.Accept {
			t.Errorf("attrs %d: Go accepts %v, Python %v", i, got, c.Accept)
		}
	}
}

func TestPythonNameRules(t *testing.T) {
	v, l := loadPython(t)
	for i, c := range v.Vectors.Names {
		// A directory read refuses an empty NAME reply in both releases;
		// the Go router applies that rule to every NAME reply.
		got := validateReply(fxpName, b64(t, c.B64), l) == nil
		if got != c.Listing {
			t.Errorf("names %d: Go accepts %v, Python listing %v", i, got, c.Listing)
		}
	}
}

func TestPythonVersionRules(t *testing.T) {
	v, _ := loadPython(t)
	for i, c := range v.Vectors.Version {
		ver, ext, err := parseVersion(b64(t, c.B64))
		if c.Result == nil {
			if err == nil {
				t.Errorf("version %d: Go accepts, Python refused", i)
			}
			continue
		}
		if err != nil || ver != c.Result.Version || !maps.Equal(ext, c.Result.Extensions) {
			t.Errorf("version %d: Go %d %v %v, Python %d %v", i, ver, ext, err, c.Result.Version, c.Result.Extensions)
		}
	}
}

func TestPythonEntryNameRule(t *testing.T) {
	v, _ := loadPython(t)
	for _, c := range v.Vectors.EntryNames {
		if got := strictName(c.Name); got != c.Safe {
			t.Errorf("%q: Go %v, Python %v", c.Name, got, c.Safe)
		}
	}
}

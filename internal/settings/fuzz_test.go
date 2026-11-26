package settings

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"reflect"
	"strings"
	"testing"
)

func seedJSON(f *testing.F) {
	for _, s := range []string{`null`, `{}`, `[]`, `"<&'>é😀\u007f"`, `[1.0,1e-05,-0,1e16,123456789012345678901]`,
		`{"b":{"z":[],"a":{}},"a":true}`, `{"font_size":14,"line_height":1.2}`, `[{"id":"hosts","w":4,"h":null}]`,
		`["host-keys:äö","reboot:x"]`, `{"schema_version":2,"theme":"noir","notepad":"x"}`, `1e400`, `"\ud800"`} {
		f.Add([]byte(s))
	}
}

// FuzzPythonJSON checks that the Python encoding of any value is ASCII,
// free of the characters a page must not see raw, and decodes to the same
// value.
func FuzzPythonJSON(f *testing.F) {
	seedJSON(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		v := jsontext.Value(in)
		if !v.IsValid() {
			return
		}
		c, err := compact(v)
		if err != nil {
			return
		}
		out, err := PythonJSON(c)
		if err != nil {
			return
		}
		for i := range len(out) {
			if out[i] >= 0x7f || out[i] < 0x20 {
				t.Fatalf("byte %#x in %q", out[i], out)
			}
		}
		if strings.ContainsAny(out, "<>&'") {
			t.Fatalf("unescaped page character in %q", out)
		}
		var a, b any
		if json.Unmarshal(c, &a) != nil {
			return
		}
		if err := json.Unmarshal([]byte(out), &b); err != nil {
			t.Fatalf("%q: output %q does not decode: %v", c, out, err)
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("%q: decodes to %v, input %v", out, b, a)
		}
	})
}

// FuzzValidators runs the value checks on arbitrary JSON: they never
// panic, and every accepted value can be stored and rendered.
func FuzzValidators(f *testing.F) {
	seedJSON(f)
	f.Fuzz(func(t *testing.T, in []byte) {
		v := jsontext.Value(in)
		if !v.IsValid() {
			return
		}
		c, err := compact(v)
		if err != nil {
			return
		}
		if ValidTerminalAppearance(c) {
			if _, err := PythonJSON(c); err != nil {
				t.Fatalf("accepted appearance %q does not encode: %v", c, err)
			}
		}
		if ValidOverviewPanels(c) {
			if kept := knownPanels(c); len(kept) == 0 && !isNull(c) && string(c) != "[]" {
				t.Fatalf("valid arrangement %q lost every panel", c)
			}
		}
		if ValidOverviewDismissed(c) && len(knownDismissed(c)) == 0 && string(c) != "[]" {
			t.Fatalf("valid list %q lost every item", c)
		}
		if doc, err := parseLegacyDocument(c); err == nil {
			if _, ok := buildUser(doc.settings); !ok {
				t.Fatalf("accepted document %q does not load", c)
			}
		}
		_, _ = parseLegacyApp(c)
	})
}

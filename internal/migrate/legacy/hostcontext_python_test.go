package legacy

import (
	"bytes"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/oracletest"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

// Differential test of entity E28 (CONDITIONS D2): every document is
// loaded by load_json_strict with _valid_document of app/host_context.py
// and by decodeStore and readContexts. Both must agree on whether the file
// is valid, and for a valid file on the notes, directories, command-set
// references and revision of every context. The Python answers are
// recorded in testdata/python_hostcontext.json.
const pythonHostContext = `
import json, sys
from pathlib import Path
from app import host_context as h
from app.storage_utils import load_json_strict
spec = json.load(sys.stdin)
out = []
for i, c in enumerate(spec):
    path = Path(c["dir"]) / ("host_context_%d.json" % i)
    path.write_text(c["doc"], encoding="utf-8")
    try:
        doc = load_json_strict(path, lambda: None, h._valid_document)
    except Exception:
        out.append(None)
        continue
    out.append(doc["hosts"])
sys.stdout.write("\n--result--\n" + json.dumps(out))
`

type hostContextCase struct {
	Dir string `json:"dir"`
	Doc string `json:"doc"`
}

type contextFields struct {
	Notes       string   `json:"notes"`
	Directories []string `json:"directories"`
	CommandSets []string `json:"command_sets"`
	Revision    int64    `json:"revision"`
}

func hostContextDocs() []string {
	ctx := func(fields string) string { return `{"version": 1, "hosts": {"p1": {` + fields + `}}}` }
	base := `"notes": "n", "directories": ["/srv"], "command_sets": ["set-1"], "revision": 3`
	long := func(s string, n int) string { return strings.Repeat(s, n) }
	q := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	dirs := func(entries ...string) string {
		return ctx(`"notes": "", "directories": [` + strings.Join(entries, ", ") + `], "command_sets": [], "revision": 1`)
	}
	sets := func(entries ...string) string {
		return ctx(`"notes": "", "directories": [], "command_sets": [` + strings.Join(entries, ", ") + `], "revision": 1`)
	}
	many := make([]string, 21)
	for i := range many {
		many[i] = q(fmt.Sprintf("/d%d", i))
	}
	docs := []string{
		ctx(base),
		`{"version": 1, "hosts": {}}`,
		`{"version": 1.0, "hosts": {"p1": {` + base + `}}}`,
		`{"version": true, "hosts": {}}`,
		`{"version": 2, "hosts": {}}`,
		`{"version": 1, "hosts": []}`,
		`{"version": 1}`,
		`[]`,
		`{"version": 1, "hosts": {"p1": {` + base + `}, "p2": {"notes": "Grüße ✓", "directories": [], "command_sets": [], "revision": 1}}}`,
		`{"version": 1, "hosts": {` + q(long("p", 128)) + `: {` + base + `}}}`,
		`{"version": 1, "hosts": {` + q(long("p", 129)) + `: {` + base + `}}}`,
		`{"version": 1, "hosts": {` + q(long("é", 128)) + `: {` + base + `}}}`,
		`{"version": 1, "hosts": {"p1": []}}`,
		// revision
		ctx(`"notes": "", "directories": [], "command_sets": [], "revision": 0`),
		ctx(`"notes": "", "directories": [], "command_sets": [], "revision": -1`),
		ctx(`"notes": "", "directories": [], "command_sets": [], "revision": 1.0`),
		ctx(`"notes": "", "directories": [], "command_sets": [], "revision": 1e0`),
		ctx(`"notes": "", "directories": [], "command_sets": [], "revision": true`),
		ctx(`"notes": "", "directories": [], "command_sets": [], "revision": "1"`),
		ctx(`"notes": "", "directories": [], "command_sets": [], "revision": 9223372036854775807`),
		ctx(`"notes": "", "directories": [], "command_sets": []`),
		// member set and repeated names (the last value wins in Python)
		ctx(`"notes": "a", "notes": "b", "directories": [], "command_sets": []`),
		ctx(`"notes": "a", "directories": [], "command_sets": [], "revision": "x", "revision": 2`),
		ctx(`"notes": "a", "directories": [], "command_sets": [], "revision": 2, "revision": 0`),
		ctx(base + `, "extra": 1`),
		ctx(`"directories": [], "command_sets": [], "revision": 1`),
		// notes
		ctx(`"notes": ` + q(long("é", 100000)) + `, "directories": [], "command_sets": [], "revision": 1`),
		ctx(`"notes": ` + q(long("a", 100001)) + `, "directories": [], "command_sets": [], "revision": 1`),
		ctx(`"notes": ` + q(long("😀", 100000)) + `, "directories": [], "command_sets": [], "revision": 1`),
		ctx(`"notes": null, "directories": [], "command_sets": [], "revision": 1`),
		ctx(`"notes": "line\nbreak\ttab", "directories": [], "command_sets": [], "revision": 1`),
		// directories
		dirs(),
		dirs(`"srv"`),
		dirs(`"/"`),
		dirs(`"/a b"`),
		dirs(`"/tab\there"`),
		dirs(q("/nbsp\u00a0x")),
		dirs(q("/zwsp\u200bx")),
		dirs(q("/soft\u00adhyphen")),
		dirs(q("/emoji😀")),
		dirs(q("/combining\u0301")),
		dirs(q("/unassigned\U000E0080")),
		dirs(q("/private\ue000")),
		dirs(q("/line\u2028sep")),
		dirs(q("/ideographic\u3000space")),
		dirs(q("/" + long("a", 4095))),
		dirs(q("/" + long("a", 4096))),
		dirs(q("/" + long("é", 2047) + "a")),
		dirs(q("/" + long("é", 2048))),
		dirs(`"/a"`, `"/a"`),
		dirs(many[:20]...),
		dirs(many...),
		dirs(`1`),
		ctx(`"notes": "", "directories": {}, "command_sets": [], "revision": 1`),
		// command-set references
		sets(`""`),
		sets(q(long("r", 128))),
		sets(q(long("r", 129))),
		sets(q(long("😀", 128))),
		sets(q(long("😀", 129))),
		sets(`"r1"`, `"r1"`),
		sets(many...),
		sets(`null`),
		sets(q("with space\u00a0and\ttab")),
	}
	return docs
}

func TestHostContextReadMatchesPython(t *testing.T) {
	t.Parallel()
	docs := hostContextDocs()
	rec := oracletest.Open(t, "testdata/python_hostcontext.json")
	want := oracletest.Ask(t, rec, "load_json_strict", docs, func(r oracletest.Release) []map[string]contextFields {
		dir := t.TempDir()
		cases := make([]hostContextCase, len(docs))
		for i, d := range docs {
			cases[i] = hostContextCase{Dir: dir, Doc: d}
		}
		in, _ := json.Marshal(cases)
		cmd := exec.CommandContext(t.Context(), r.Python, "-c", pythonHostContext) // #nosec G204 -- test oracle
		cmd.Dir = r.Root
		cmd.Env = append(os.Environ(), "DATA_DIR="+filepath.Join(dir, "data"), "SECRET_KEY=differential-test-only-0123456789abcdef", "PYTHONDONTWRITEBYTECODE=1")
		cmd.Stdin = bytes.NewReader(in)
		raw, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("python: %v\n%s", err, raw)
		}
		_, result, ok := strings.Cut(string(raw), "\n--result--\n")
		if !ok {
			t.Fatalf("python output: %s", raw)
		}
		var answer []map[string]contextFields
		if err := json.Unmarshal([]byte(result), &answer); err != nil {
			t.Fatal(err)
		}
		if len(answer) != len(docs) {
			t.Fatalf("%d results for %d documents", len(answer), len(docs))
		}
		for _, contexts := range answer {
			for id, c := range contexts {
				c.Notes = shortNotes(c.Notes)
				contexts[id] = c
			}
		}
		return answer
	})
	valid := 0
	for i, d := range docs {
		got, gotValid := goHostContexts(d)
		label := d
		if len(label) > 160 {
			label = label[:160] + "…"
		}
		if gotValid != (want[i] != nil) {
			t.Errorf("case %d %s: Go valid %v, Python valid %v", i, label, gotValid, want[i] != nil)
			continue
		}
		if !gotValid {
			continue
		}
		valid++
		if len(got) != len(want[i]) {
			t.Errorf("case %d %s: %d contexts, Python %d", i, label, len(got), len(want[i]))
		}
		for id, w := range want[i] {
			g, ok := got[id]
			if !ok || shortNotes(g.Notes) != w.Notes || g.Revision != w.Revision ||
				!slices.Equal(g.Directories, nonNilList(w.Directories)) || !slices.Equal(g.CommandSets, nonNilList(w.CommandSets)) {
				t.Errorf("case %d %s: context %q\n got %+v\nwant %+v", i, label, id, g, w)
			}
		}
	}
	if valid == 0 || valid == len(docs) {
		t.Fatalf("%d of %d documents valid; the cases must cover both outcomes", valid, len(docs))
	}
}

// shortNotes keeps notes up to 1 KiB and replaces longer ones by their
// length and SHA-256, which keeps the recording small.
func shortNotes(notes string) string {
	if len(notes) <= 1024 {
		return notes
	}
	sum := sha256.Sum256([]byte(notes))
	return fmt.Sprintf("%d bytes, sha256 %x", len(notes), sum)
}

// goHostContexts reads one document like the E28 step, with every context
// belonging to an existing profile.
func goHostContexts(doc string) (map[string]contextFields, bool) {
	spec := userStores[slices.IndexFunc(userStores, func(s storeSpec) bool { return s.name == "host_context" })]
	d, err := decodeStore([]byte(doc), spec)
	if err != nil {
		return nil, false
	}
	var ids []string
	if hostsValue, ok := pyjson.Get(d.Raw, "hosts"); ok {
		members, _ := pyjson.Members(hostsValue)
		for _, m := range members {
			ids = append(ids, m.Name)
		}
	}
	var s hostNotesStep
	if err := s.readContexts(1, d.Raw, ids); err != nil {
		return nil, false
	}
	out := map[string]contextFields{}
	for _, c := range s.contexts {
		out[c.profileID] = contextFields{Directories: nonNilList(c.directories), CommandSets: nonNilList(c.commandSets), Revision: c.revision}
	}
	for _, n := range s.notes {
		f := out[n.profileID]
		f.Notes = n.body
		out[n.profileID] = f
	}
	return out, true
}

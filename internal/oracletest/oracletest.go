// Package oracletest replays the recorded answers of the Python release
// for the differential tests, and asks the release itself on request.
// Only test files import it (architecture tests).
//
// The mode comes from WEBSSH_PYTHON_ORACLE:
//
//	(unset)  replay: every answer comes from its recording under testdata
//	         and no interpreter is started
//	live     every answer is asked from the Python release and must equal
//	         its recording; a missing interpreter fails the test
//	record   every answer is asked and the recordings are written again
//	         (scripts/record-python-oracles.sh)
//
// WEBSSH_PYTHON names the interpreter of the Python release with
// requirements-test.txt installed; it defaults to .venv/bin/python in the
// repository root. WEBSSH_PYTHON_ROOT names the checkout that holds the
// Python sources (app/, config.py); it defaults to the repository root and
// points to a worktree of the last Python release once app/ is gone.
// Recording also needs WEBSSH_PYTHON_ORACLE_SOURCE, the commit of the
// Python sources, and WEBSSH_PYTHON_ORACLE_VERSION, the version of the
// interpreter; both go into the header of each file. The package starts
// no process itself (architecture tests); the tests' oracles do.
package oracletest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
)

// Environment variables of the oracle.
const (
	ModeEnv   = "WEBSSH_PYTHON_ORACLE"
	PythonEnv = "WEBSSH_PYTHON"
	RootEnv   = "WEBSSH_PYTHON_ROOT"
	SourceEnv = "WEBSSH_PYTHON_ORACLE_SOURCE"
	// VersionEnv is the version of the interpreter of a recording.
	VersionEnv = "WEBSSH_PYTHON_ORACLE_VERSION"
)

// Mode is how answers of the Python release are obtained.
type Mode string

// The modes of WEBSSH_PYTHON_ORACLE.
const (
	Replay Mode = ""
	Live   Mode = "live"
	Record Mode = "record"
)

const recorder = "scripts/record-python-oracles.sh"

// CurrentMode returns the mode of this run. An unknown value fails the
// test, so that a typo cannot fall back to replay unnoticed.
func CurrentMode(t testing.TB) Mode {
	t.Helper()
	switch m := Mode(os.Getenv(ModeEnv)); m {
	case Replay, Live, Record:
		return m
	default:
		t.Fatalf("oracletest: %s=%q; want unset, live or record", ModeEnv, m)
		return Replay
	}
}

// Release is what an oracle needs to run the Python release.
type Release struct {
	// Python is the absolute path of the interpreter.
	Python string
	// Root is the checkout of the Python sources (app/, config.py).
	Root string
}

// RepoRoot returns the directory of go.mod above the working directory.
func RepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("oracletest: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("oracletest: no go.mod above the working directory")
		}
		dir = parent
	}
}

// release finds the interpreter. It never skips: a run that asks the
// Python release fails without it.
func release(t testing.TB) Release {
	t.Helper()
	repo := RepoRoot(t)
	python := os.Getenv(PythonEnv)
	if python == "" {
		python = filepath.Join(repo, ".venv", "bin", "python")
	}
	abs, err := filepath.Abs(python)
	if err == nil {
		_, err = os.Stat(abs)
	}
	if err != nil {
		t.Fatalf("oracletest: %s=%s needs the Python release (%s): %v", ModeEnv, CurrentMode(t), PythonEnv, err)
	}
	root := repo
	if r := os.Getenv(RootEnv); r != "" {
		if root, err = filepath.Abs(r); err != nil {
			t.Fatalf("oracletest: %s: %v", RootEnv, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "app", "__init__.py")); err != nil {
		t.Fatalf("oracletest: no Python release in %s (%s): %v", root, RootEnv, err)
	}
	return Release{Python: abs, Root: root}
}

// RequireLive returns the Python release for a check that has no
// recording and only runs against the live release, for example a run
// over random inputs. In replay mode the test is skipped with the reason;
// in live and record mode a missing interpreter fails it.
func RequireLive(t testing.TB) Release {
	t.Helper()
	if CurrentMode(t) == Replay {
		t.Skipf("compares with the live Python release only (%s=live)", ModeEnv)
	}
	return release(t)
}

// Header says where the answers of a recording come from.
type Header struct {
	Python   string `json:"python"`
	Source   string `json:"source"`
	Recorder string `json:"recorder"`
}

type entry struct {
	Request string         `json:"request_sha256"`
	Answer  jsontext.Value `json:"answer"`
}

type document struct {
	Oracle Header           `json:"oracle"`
	Cases  map[string]entry `json:"cases"`
}

// Recording is one file of recorded answers.
type Recording struct {
	path string
	mode Mode

	mu      sync.Mutex
	doc     document
	release *Release
}

// Open reads the recording at path, relative to the package directory. In
// record mode it starts empty and is written when t and its subtests end.
func Open(t *testing.T, path string) *Recording {
	t.Helper()
	r := &Recording{path: path, mode: CurrentMode(t), doc: document{Cases: map[string]entry{}}}
	if r.mode == Record {
		source, version := os.Getenv(SourceEnv), os.Getenv(VersionEnv)
		if source == "" || version == "" {
			t.Fatalf("oracletest: recording needs %s and %s (run %s)", SourceEnv, VersionEnv, recorder)
		}
		rel := release(t)
		r.release = &rel
		r.doc.Oracle = Header{Python: version, Source: source, Recorder: recorder}
		t.Cleanup(func() { r.write(t) })
		return r
	}
	raw, err := os.ReadFile(path) // #nosec G304 -- a recording under the package's testdata
	if err != nil {
		t.Fatalf("oracletest: %v (record it with %s)", err, recorder)
	}
	if err := json.Unmarshal(raw, &r.doc, json.RejectUnknownMembers(true)); err != nil {
		t.Fatalf("oracletest: %s: %v", path, err)
	}
	if r.doc.Oracle.Python == "" || r.doc.Oracle.Source == "" {
		t.Fatalf("oracletest: %s has no Python version or source in its header", path)
	}
	return r
}

// Header returns the header of the recording.
func (r *Recording) Header() Header {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.doc.Oracle
}

// Ask returns the Python release's answer to request under key. ask runs
// the release and must return a deterministic answer: anything random,
// such as generated identifiers or temporary paths, is normalised by ask.
// The request is everything the answer depends on besides the Python
// sources; its digest must be the recorded one, so a changed test input
// cannot be compared with stale answers.
func Ask[A any](t testing.TB, r *Recording, key string, request any, ask func(Release) A) A {
	t.Helper()
	digest := requestDigest(t, request)
	// Every mode hands the test the answer as it reads back from its
	// recording, so that record, live and replay see the same values.
	if r.mode == Record {
		encoded := encode(t, ask(r.liveRelease(t)))
		r.mu.Lock()
		if _, dup := r.doc.Cases[key]; dup {
			r.mu.Unlock()
			t.Fatalf("oracletest: %s: key %q recorded twice", r.path, key)
		}
		r.doc.Cases[key] = entry{Request: digest, Answer: encoded}
		r.mu.Unlock()
		return decode[A](t, r.path, key, encoded)
	}
	r.mu.Lock()
	e, ok := r.doc.Cases[key]
	r.mu.Unlock()
	switch {
	case !ok:
		t.Fatalf("oracletest: %s has no answer for %q; record it with %s", r.path, key, recorder)
	case e.Request != digest:
		t.Fatalf("oracletest: %s: the request for %q changed since it was recorded; record it again with %s", r.path, key, recorder)
	}
	recorded := decode[A](t, r.path, key, e.Answer)
	if r.mode == Replay {
		return recorded
	}
	live := encode(t, ask(r.liveRelease(t)))
	if rec := encode(t, recorded); !bytes.Equal(live, rec) {
		t.Errorf("oracletest: the live Python release answers %q differently from %s:\n live     %s\n recorded %s",
			key, r.path, shorten(live), shorten(rec))
	}
	return decode[A](t, r.path, key, live)
}

func decode[A any](t testing.TB, path, key string, v jsontext.Value) A {
	t.Helper()
	var a A
	if err := json.Unmarshal(v, &a); err != nil {
		t.Fatalf("oracletest: %s: answer for %q: %v", path, key, err)
	}
	return a
}

func (r *Recording) liveRelease(t testing.TB) Release {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.release == nil {
		rel := release(t)
		r.release = &rel
	}
	return *r.release
}

func (r *Recording) write(t testing.TB) {
	t.Helper()
	if t.Failed() {
		t.Errorf("oracletest: %s not written because the test failed", r.path)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out, err := r.doc.format()
	if err != nil {
		t.Fatalf("oracletest: %s: %v", r.path, err)
	}
	if err := os.MkdirAll(filepath.Dir(r.path), 0o750); err != nil {
		t.Fatalf("oracletest: %v", err)
	}
	if err := os.WriteFile(r.path, out, 0o600); err != nil {
		t.Fatalf("oracletest: %v", err)
	}
}

// format writes the document with sorted keys and one case per member.
// An answer that is an array, or a large object, gets one compact element
// or member per line, so that a changed answer shows as a small diff.
func (d document) format() ([]byte, error) {
	var b bytes.Buffer
	header, err := json.Marshal(d.Oracle, json.Deterministic(true), jsontext.WithIndent("  "), jsontext.WithIndentPrefix("  "))
	if err != nil {
		return nil, err
	}
	b.WriteString("{\n  \"oracle\": ")
	b.Write(header)
	b.WriteString(",\n  \"cases\": {")
	for i, key := range slices.Sorted(maps.Keys(d.Cases)) {
		e := d.Cases[key]
		name, err := jsontext.AppendQuote(nil, key)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\n    %s: {\n      \"request_sha256\": %q,\n      \"answer\": ", name, e.Request)
		if err := writeAnswer(&b, e.Answer); err != nil {
			return nil, err
		}
		b.WriteString("\n    }")
	}
	b.WriteString("\n  }\n}\n")
	return b.Bytes(), nil
}

// splitObjects is the size above which an object answer is written one
// member per line.
const splitObjects = 1024

func writeAnswer(b *bytes.Buffer, answer jsontext.Value) error {
	const indent = "\n        "
	switch {
	case answer.Kind() == '[':
		var items []jsontext.Value
		if err := json.Unmarshal(answer, &items); err != nil {
			return err
		}
		if len(items) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteString("[")
		for i, item := range items {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(indent)
			b.Write(item)
		}
		b.WriteString("\n      ]")
	case answer.Kind() == '{' && len(answer) > splitObjects:
		var members map[string]jsontext.Value
		if err := json.Unmarshal(answer, &members); err != nil {
			return err
		}
		b.WriteString("{")
		for i, name := range slices.Sorted(maps.Keys(members)) {
			quoted, err := jsontext.AppendQuote(nil, name)
			if err != nil {
				return err
			}
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(indent)
			b.Write(quoted)
			b.WriteByte(':')
			b.Write(members[name])
		}
		b.WriteString("\n      }")
	default:
		b.Write(answer)
	}
	return nil
}

// encode is the deterministic, compact form of v used for comparisons.
// Nil maps and slices stay null, so that a recorded answer keeps the
// difference between nothing and empty.
func encode(t testing.TB, v any) jsontext.Value {
	t.Helper()
	out, err := json.Marshal(v, json.Deterministic(true), json.FormatNilMapAsNull(true), json.FormatNilSliceAsNull(true))
	if err != nil {
		t.Fatalf("oracletest: encode: %v", err)
	}
	return out
}

func requestDigest(t testing.TB, request any) string {
	t.Helper()
	sum := sha256.Sum256(encode(t, request))
	return hex.EncodeToString(sum[:])
}

func shorten(v []byte) string {
	const limit = 600
	if len(v) > limit {
		return string(v[:limit]) + "…"
	}
	return string(v)
}

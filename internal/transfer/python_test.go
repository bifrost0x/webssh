package transfer_test

import (
	"context"
	json "encoding/json/v2"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/files/filestest"
	"github.com/bifrost0x/webssh/internal/transfer"
)

// testdata/python_conflicts.json is produced by
// testdata/python_conflicts.py from app/remote_transfer.py: the outcome
// of every combination of source entry, destination state, conflict
// policy and limit, and the destination tree after.
type pyConflicts struct {
	Dispositions map[string]string               `json:"dispositions"`
	Source       map[string][2]string            `json:"source"`
	Destinations map[string]map[string][2]string `json:"destinations"`
	Limits       map[string][2]int64             `json:"limits"`
	Vectors      []struct {
		Source      string   `json:"source"`
		Destination string   `json:"destination"`
		Target      string   `json:"target"`
		Policy      string   `json:"policy"`
		Limit       string   `json:"limit"`
		Code        string   `json:"code"`
		Tree        []string `json:"tree"`
	} `json:"vectors"`
}

// pyBackend has the replace rules the vectors were made with (those of
// the SFTP backend): a replace refuses anything but a regular file.
type pyBackend struct{ *filestest.Backend }

func (b pyBackend) Write(ctx context.Context, p string, src io.Reader, o files.WriteOptions) (files.WriteResult, error) {
	if e, err := b.Stat(ctx, p, false); err == nil {
		if o.Exclusive {
			return files.WriteResult{}, fault.New(fault.FileConflict, "")
		}
		if e.IsDir || e.IsSymlink {
			return files.WriteResult{}, fault.New(fault.AtomicReplaceUnavailable, "")
		}
	}
	return b.Backend.Write(ctx, p, src, o)
}

func pyTree(spec map[string][2]string) *filestest.Backend {
	b := filestest.New()
	for _, p := range slices.Sorted(func(yield func(string) bool) {
		for k := range spec {
			if !yield(k) {
				return
			}
		}
	}) {
		switch n := spec[p]; n[0] {
		case "file":
			b.PutFile(p, []byte(n[1]))
		case "link":
			b.PutLink(p, n[1])
		case "dir":
			b.PutFile(p+"/.placeholder", nil)
			_ = b.Remove(context.Background(), p+"/.placeholder", false, files.Budget{})
		}
	}
	return b
}

// dumpTree lists b like the vector script: path and kind, file contents.
func dumpTree(t *testing.T, b *filestest.Backend) []string {
	t.Helper()
	var entries []files.Entry
	err := b.Walk(t.Context(), "/", files.Budget{MaxMembers: 1000}, func(e files.Entry) error {
		entries = append(entries, e)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		switch {
		case e.IsSymlink:
			out = append(out, e.Path+" link")
		case e.IsDir:
			out = append(out, e.Path+" dir")
		default:
			data, _ := b.File(e.Path)
			out = append(out, e.Path+" file "+string(data))
		}
	}
	slices.Sort(out)
	return out
}

// pythonFixes are the outcomes Go reports on purpose differently: a
// replace that the destination cannot do safely is
// ATOMIC_REPLACE_UNAVAILABLE, as Python reported it for SMB, where its
// SFTP path wrapped it into TRANSFER_UNAVAILABLE.
func pythonFix(pyCode string, goCode fault.Code) bool {
	return pyCode == "TRANSFER_UNAVAILABLE" && goCode == fault.AtomicReplaceUnavailable
}

func TestPythonCopyAndConflictRules(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/python_conflicts.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc pyConflicts
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) < 200 {
		t.Fatalf("%d vectors", len(doc.Vectors))
	}
	fixes := 0
	for i, v := range doc.Vectors {
		name := fmt.Sprintf("%d %s→%s(%s) %s %s", i, v.Source, v.Destination, v.Target, v.Policy, v.Limit)
		limit := doc.Limits[v.Limit]
		e := newEnv(t, func(o *transfer.Options) {
			o.Limits = transfer.DefaultLimits
			o.Limits.MaxArchive, o.Limits.MaxMembers = limit[0], int(limit[1])
		})
		src := pyTree(doc.Source)
		dst := src
		destID := "sftp-session:a"
		if v.Destination != "same" {
			dst = pyTree(doc.Destinations[v.Destination])
			destID = "smb-quick:b"
		}
		e.src.add("sftp-session:a", e.owner, pyBackend{src})
		if destID != "sftp-session:a" {
			e.src.add(destID, e.owner, pyBackend{dst})
		}
		id, err := e.m.Copy(t.Context(), e.caller(), transfer.CopyRequest{
			SourceID: "sftp-session:a", SourcePath: v.Source, DestID: destID, DestPath: v.Target,
			RequestID: "r", Policy: transfer.ConflictPolicy(v.Policy),
		})
		if err != nil {
			t.Fatalf("%s: start: %v", name, err)
		}
		ev := e.ev.wait(t, id)
		code := "OK"
		if ev.Failure != nil {
			code = string(ev.Failure.Code)
		}
		if code != v.Code {
			if ev.Failure != nil && pythonFix(v.Code, ev.Failure.Code) {
				fixes++
			} else {
				t.Errorf("%s: code %s, Python %s", name, code, v.Code)
			}
		}
		want := make([]string, len(v.Tree))
		for j, line := range v.Tree {
			if i := strings.Index(line, " link "); i > 0 {
				line = line[:i+len(" link")]
			}
			want[j] = line
		}
		if got := dumpTree(t, dst); !slices.Equal(got, want) {
			t.Errorf("%s: tree\n%v\nPython\n%v", name, got, want)
		}
		e.idle()
	}
	t.Logf("%d vectors, %d reported as ATOMIC_REPLACE_UNAVAILABLE", len(doc.Vectors), fixes)
}

func TestPythonContentDisposition(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile("testdata/python_conflicts.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc pyConflicts
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Dispositions) < 10 {
		t.Fatalf("%d names", len(doc.Dispositions))
	}
	for name, want := range doc.Dispositions {
		if got := transfer.ContentDisposition(name); got != want {
			t.Errorf("%q: %s, Python %s", name, got, want)
		}
	}
}

package legacy

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/keyring"
)

// A SIGKILL at every step of a purge leaves a state the next start
// completes: S10 resumes the removal from the stored list without
// evaluating the partly removed legacy source, and --replace and
// --dry-run are refused meanwhile (I-26); the material ends in go/ with
// one copy (I-25).
func TestCrashDuringPurge(t *testing.T) {
	t.Parallel()
	// RS4-07: besides the first, the crash also hits the second and the
	// last removed file.
	removed := 0
	o := migratedForPurge(t)
	o.checkpoint = func(p string) {
		if p == PointPurgeRemoved {
			removed++
		}
	}
	if _, err := Purge(t.Context(), PurgeOptions{Options: o, SkipBackup: true}); err != nil {
		t.Fatal(err)
	}
	if removed < 3 {
		t.Fatalf("the purge removed %d files; the test needs at least 3", removed)
	}
	points := []string{PointPurgeStarted, PointPurgeRemoved, PointPurgeRemoved + "#2",
		PointPurgeRemoved + "#" + strconv.Itoa(removed), PointPurgeRecorded, PointPurgeMaterial}
	for _, point := range points {
		t.Run(point, func(t *testing.T) {
			t.Parallel()
			o := migratedForPurge(t)
			crashAt(t, "purge", point, o)
			ev := evaluateOnly(t, o)
			switch base, _, _ := strings.Cut(point, "#"); base {
			case PointPurgeStarted, PointPurgeRemoved:
				if ev.state != S10 {
					t.Fatalf("state %s, want S10", ev.state)
				}
				if _, err := Replace(t.Context(), o); stopCode(err) != CodePurgeInProgress {
					t.Errorf("replace in S10: %v", err)
				}
				if _, err := DryRun(t.Context(), o); stopCode(err) != CodePurgeInProgress {
					t.Errorf("dry run in S10: %v", err)
				}
			default:
				if ev.state != S4 {
					t.Fatalf("state %s, want S4", ev.state)
				}
			}
			st, err := startClosed(o)
			if err != nil || st.State != S4 {
				t.Fatalf("start: %+v, %v", st, err)
			}
			if p, err := legacyPresence(o.DataDir); err != nil || p != legacyNone {
				t.Errorf("legacy presence %v, %v", p, err)
			}
			l := mustLayout(t, o.DataDir)
			if _, err := os.Stat(filepath.Join(l.goDir, keyring.MaterialName)); err != nil {
				t.Errorf("material not in go/: %v", err)
			}
			if _, err := os.Lstat(l.stateDir); !os.IsNotExist(err) {
				t.Errorf("logs/.webssh-go/ left: %v", err)
			}
		})
	}
}

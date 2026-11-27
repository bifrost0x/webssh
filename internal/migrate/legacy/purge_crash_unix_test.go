package legacy

import (
	"os"
	"path/filepath"
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
	for _, point := range []string{PointPurgeStarted, PointPurgeRemoved, PointPurgeRecorded, PointPurgeMaterial} {
		t.Run(point, func(t *testing.T) {
			t.Parallel()
			o := migratedForPurge(t)
			crashAt(t, "purge", point, o)
			ev := evaluateOnly(t, o)
			switch point {
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

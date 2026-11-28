package sftp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// A directory of the target replaced by a link while a write runs does not
// redirect the staging file or the rename into the link target.
func TestWriteRefusesParentReplacedDuringWrite(t *testing.T) {
	for _, exists := range []bool{true, false} {
		base, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(base, "home-alice", ".ssh")
		conf := filepath.Join(base, "drop", "conf")
		for _, d := range []string{victim, conf} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		put(t, filepath.Join(victim, "authorized_keys"), []byte("alice\n"), 0o600)
		put(t, filepath.Join(victim, "rc.keep"), nil, 0o600)
		if exists {
			put(t, filepath.Join(conf, "authorized_keys"), []byte("old\n"), 0o600)
			put(t, filepath.Join(victim, "rc"), []byte("alice\n"), 0o600)
		}
		target := filepath.Join(conf, "authorized_keys")
		if !exists {
			target = filepath.Join(conf, "rc")
		}
		fired := false
		b := hooked(t, true, once(1, func(typ byte, p string) bool { return typ == fxpLstat && p == target }, func() {
			fired = true
			swapToLink(t, conf, filepath.Join(base, "parked"), victim)
		}))
		_, err = b.Write(ctx(t), target, strings.NewReader("mallory\n"), files.WriteOptions{Size: 8})
		if !fired {
			t.Fatal("the swap never ran")
		}
		for _, n := range []string{"authorized_keys", "rc"} {
			if got, _ := os.ReadFile(filepath.Join(victim, n)); strings.Contains(string(got), "mallory") {
				t.Errorf("exists=%v: %s of the victim written through the link", exists, n)
			}
		}
		ents, _ := os.ReadDir(victim)
		if len(ents) > 3 {
			t.Errorf("exists=%v: staging file left in the link target: %v", exists, ents)
		}
		if !fault.Is(err, fault.SourceChanged) {
			t.Errorf("exists=%v: Write = %v, want %s", exists, err, fault.SourceChanged)
		}
	}
}

package sftp

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

// raceTree is a shared project directory with a child directory z_dir
// that a local user may replace, and a victim's home beside it.
type raceTree struct {
	base, root, victim string
}

func newRaceTree(t *testing.T) raceTree {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rt := raceTree{base: base, root: filepath.Join(base, "shared", "project"), victim: filepath.Join(base, "home-alice")}
	for _, d := range []string{filepath.Join(rt.victim, "docs"), filepath.Join(rt.root, "a_dir"), filepath.Join(rt.root, "z_dir")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{
		filepath.Join(rt.victim, "f"), filepath.Join(rt.victim, "important.txt"),
		filepath.Join(rt.victim, "docs", "thesis.tex"), filepath.Join(rt.root, "a_dir", "f"),
		filepath.Join(rt.root, "z_dir", "own"),
	} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return rt
}

func (rt raceTree) victimIntact(t *testing.T) {
	t.Helper()
	for _, p := range []string{"f", "important.txt", "docs/thesis.tex"} {
		if _, err := os.Lstat(filepath.Join(rt.victim, p)); err != nil {
			t.Errorf("%s outside the tree was removed: %v", p, err)
		}
	}
}

// once returns a hook that runs fn at the n-th request (1-based) that
// match accepts.
func once(n int, match func(typ byte, p string) bool, fn func()) func(byte, string) {
	var mu sync.Mutex
	seen := 0
	return func(typ byte, p string) {
		mu.Lock()
		defer mu.Unlock()
		if !match(typ, p) {
			return
		}
		seen++
		if seen == n {
			fn()
		}
	}
}

// A directory replaced by a link after the listing was read is not
// entered: the type of READDIR is stale, the backend asks again.
func TestRemoveRechecksDirectoryReplacedAfterListing(t *testing.T) {
	rt := newRaceTree(t)
	fired := false
	// The first CLOSE ends the listing of the root.
	b := hooked(t, false, once(1, func(typ byte, _ string) bool { return typ == fxpClose }, func() {
		fired = true
		swapToLink(t, filepath.Join(rt.root, "z_dir"), filepath.Join(rt.base, "parked"), rt.victim)
	}))
	err := b.Remove(ctx(t), rt.root, true, files.Budget{})
	if !fired {
		t.Fatal("the swap never ran")
	}
	rt.victimIntact(t)
	if err != nil {
		t.Fatalf("Remove = %v; the link should be removed as a link", err)
	}
	if _, err := os.Lstat(filepath.Join(rt.base, "parked", "own")); err != nil {
		t.Errorf("the parked directory was touched: %v", err)
	}
}

// A directory replaced between its fresh LSTAT and OPENDIR is noticed by
// the canonical path check (REALPATH resolves links on a real server).
func TestRemoveRefusesDirectoryReplacedBeforeDescent(t *testing.T) {
	rt := newRaceTree(t)
	zdir := filepath.Join(rt.root, "z_dir")
	fired := false
	b := hooked(t, true, once(1, func(typ byte, p string) bool {
		return typ != fxpLstat && p == zdir
	}, func() {
		fired = true
		swapToLink(t, zdir, filepath.Join(rt.base, "parked"), rt.victim)
	}))
	err := b.Remove(ctx(t), rt.root, true, files.Budget{})
	if !fired {
		t.Fatal("the swap never ran")
	}
	rt.victimIntact(t)
	if !fault.Is(err, fault.SourceChanged) {
		t.Fatalf("Remove = %v, want %s", err, fault.SourceChanged)
	}
}

// A directory replaced after it was listed and before its files are
// removed is noticed before the first REMOVE.
func TestRemoveRefusesParentReplacedBeforeRemove(t *testing.T) {
	rt := newRaceTree(t)
	adir := filepath.Join(rt.root, "a_dir")
	fired := false
	// The second request naming a_dir itself, other than LSTAT, comes
	// after its listing: the check before the REMOVE of a_dir/f. Before
	// the fix the first request below a_dir is that REMOVE.
	n, seen := 2, 0
	b := hooked(t, true, func(typ byte, p string) {
		if fired || typ == fxpLstat || typ == fxpReaddir || typ == fxpClose {
			return
		}
		switch {
		case p == adir:
			seen++
		case strings.HasPrefix(p, adir+"/"):
			seen = n
		default:
			return
		}
		if seen >= n {
			fired = true
			swapToLink(t, adir, filepath.Join(rt.base, "parked"), rt.victim)
		}
	})
	err := b.Remove(ctx(t), rt.root, true, files.Budget{})
	if !fired {
		t.Fatal("the swap never ran")
	}
	rt.victimIntact(t)
	if !fault.Is(err, fault.SourceChanged) {
		t.Fatalf("Remove = %v, want %s", err, fault.SourceChanged)
	}
}

// Walk reports a directory replaced by a link as a link and does not
// enter it.
func TestWalkRechecksDirectoryReplacedAfterListing(t *testing.T) {
	rt := newRaceTree(t)
	b := hooked(t, false, once(1, func(typ byte, _ string) bool { return typ == fxpClose }, func() {
		swapToLink(t, filepath.Join(rt.root, "z_dir"), filepath.Join(rt.base, "parked"), rt.victim)
	}))
	var seen []string
	err := b.Walk(ctx(t), rt.root, files.Budget{}, func(e files.Entry) error {
		seen = append(seen, strings.TrimPrefix(e.Path, rt.root))
		if e.Path == filepath.Join(rt.root, "z_dir") && !e.IsSymlink {
			t.Errorf("z_dir reported as %+v, want a link", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range seen {
		if strings.HasPrefix(s, "/z_dir/") {
			t.Fatalf("Walk entered the swapped directory: %v", seen)
		}
	}
}

// The same on a server that resolves links: the swap between LSTAT and
// OPENDIR stops the walk.
func TestWalkRefusesDirectoryReplacedBeforeDescent(t *testing.T) {
	rt := newRaceTree(t)
	zdir := filepath.Join(rt.root, "z_dir")
	b := hooked(t, true, once(1, func(typ byte, p string) bool {
		return typ != fxpLstat && p == zdir
	}, func() {
		swapToLink(t, zdir, filepath.Join(rt.base, "parked"), rt.victim)
	}))
	err := b.Walk(ctx(t), rt.root, files.Budget{}, func(e files.Entry) error {
		if strings.HasPrefix(e.Path, zdir+"/") {
			t.Errorf("Walk entered the swapped directory: %s", e.Path)
		}
		return nil
	})
	if !fault.Is(err, fault.SourceChanged) {
		t.Fatalf("Walk = %v, want %s", err, fault.SourceChanged)
	}
}

// Paths in a tree whose root sits below a link keep working: the check
// compares canonical forms.
func TestRemoveBelowLinkedRoot(t *testing.T) {
	rt := newRaceTree(t)
	link := filepath.Join(rt.base, "via")
	if err := os.Symlink(filepath.Join(rt.base, "shared"), link); err != nil {
		t.Fatal(err)
	}
	b := hooked(t, true, func(byte, string) {})
	if err := b.Remove(ctx(t), filepath.Join(link, "project"), true, files.Budget{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(rt.root); !os.IsNotExist(err) {
		t.Fatalf("tree still there: %v", err)
	}
	rt.victimIntact(t)
}

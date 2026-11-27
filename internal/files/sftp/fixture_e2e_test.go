//go:build e2e

package sftp

import (
	"testing"
	"time"
)

// The fixture serves the real backend: the probe passes, the home
// directory is the fixture's, its files are listed, and the channels end
// with the session.
func TestFixtureServesTheBackend(t *testing.T) {
	done := make(chan struct{})
	f, err := NewFixture(done, "/home/fixture", FixtureFile{Path: "/home/fixture/reload-proof.txt", Data: "reload proof"})
	if err != nil {
		t.Fatal(err)
	}
	if err := Probe(t.Context(), f, Options{}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	sub, err := f.Subsystem(t.Context(), "sftp")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(t.Context(), sub, Options{})
	if err != nil {
		t.Fatal(err)
	}
	home, err := b.Home(t.Context())
	if err != nil || home != "/home/fixture" {
		t.Fatalf("home %q %v", home, err)
	}
	l, err := b.OpenListing(t.Context(), home)
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := l.Next(t.Context(), 50)
	if err != nil || len(entries) != 1 || entries[0].Name != "reload-proof.txt" || entries[0].Size != 12 {
		t.Fatalf("listing %+v %v", entries, err)
	}
	_ = l.Close()
	if _, err := f.Subsystem(t.Context(), "exec"); err == nil {
		t.Fatal("a subsystem other than sftp was served")
	}
	ch, err := f.Subsystem(t.Context(), "sftp")
	if err != nil {
		t.Fatal(err)
	}
	close(done)
	read := make(chan error, 1)
	go func() {
		_, err := ch.Read(make([]byte, 1))
		read <- err
	}()
	select {
	case err := <-read:
		if err == nil {
			t.Fatal("read after the session ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the channel outlived the session")
	}
	if _, err := f.Subsystem(t.Context(), "sftp"); err == nil {
		t.Fatal("a subsystem opened after the session ended")
	}
}

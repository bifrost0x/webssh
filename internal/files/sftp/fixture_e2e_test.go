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

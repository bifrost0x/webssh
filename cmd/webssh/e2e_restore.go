//go:build e2e

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"

	"github.com/bifrost0x/webssh/internal/files/sftp"
	"github.com/bifrost0x/webssh/internal/hostops"
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/terminal"
)

// The stand-in remote host of the restore fixture sessions
// (e2e.workspace_restore), as tests/e2e/workspace_restore.py fakes the
// SFTP probe, the home directory, the listing, the session insights and
// the runtime inventory for the Python release. Authentication,
// restoration and transport stay real.

const fixtureHome = "/home/fixture"

var fixtureFile = sftp.FixtureFile{Path: fixtureHome + "/reload-proof.txt", Data: "reload proof"}

// The samples workspace_restore.py returns, in the output format of the
// collectors (internal/hostops).
const (
	fixtureStats = "cpu=200 0 150 950\nos_name=Reload fixture Linux\nuptime_seconds=3600\n" +
		"mem_total_kib=1024\nmem_available_kib=512\n" +
		"disk_total_kib=1024\ndisk_used_kib=512\ndisk_available_kib=512\ndisk_percent=50\n"
	fixtureInventory = "systemd_state=running\nsystemd_total=0\nsystemd_active=0\nsystemd_failed=0\nsystemd_returned=0\n"
)

func init() { fixtureFiles = restoreFixtureFiles }

// restoreFixtures holds one file system per live fixture session; it is
// dropped when the session ends.
var restoreFixtures = struct {
	sync.Mutex
	byID map[string]*sftp.Fixture
}{byID: map[string]*sftp.Fixture{}}

func restoreFixture(id string, done <-chan struct{}) (*sftp.Fixture, error) {
	restoreFixtures.Lock()
	defer restoreFixtures.Unlock()
	if f := restoreFixtures.byID[id]; f != nil {
		return f, nil
	}
	f, err := sftp.NewFixture(done, fixtureHome, fixtureFile)
	if err != nil {
		return nil, err
	}
	restoreFixtures.byID[id] = f
	go func() {
		<-done
		restoreFixtures.Lock()
		delete(restoreFixtures.byID, id)
		restoreFixtures.Unlock()
	}()
	return f, nil
}

func restoreFixtureFiles(m *terminal.Manager, owner int64, id string) (sftp.Session, bool) {
	s, ok := m.RestoreFixture(owner, id)
	if !ok {
		return sftp.Session{}, false
	}
	f, err := restoreFixture(id, s.Done)
	if err != nil {
		return sftp.Session{}, false
	}
	return sftp.Session{Conn: f, Name: s.Name, InputIdle: s.InputIdle,
		Hop: client.Hop{Host: s.Host, Port: s.Port, User: s.Username}}, true
}

func restoreFixtureLive(m *terminal.Manager, owner int64, id string) (hostops.Live, bool) {
	s, ok := m.RestoreFixture(owner, id)
	if !ok {
		return hostops.Live{}, false
	}
	return hostops.Live{Exec: fixtureExec{}, Host: s.Host, Port: s.Port, Username: s.Username,
		ProfileID: s.ProfileID, Done: s.Done}, true
}

// fixtureExec answers the collector programs of the insights and the
// runtime inventory, which arrive on stdin, with the fixture's samples.
type fixtureExec struct{}

func (fixtureExec) Exec(ctx context.Context, _ string, stdin io.Reader, stdout, _ io.Writer) (int, error) {
	if err := ctx.Err(); err != nil {
		return -1, err
	}
	var program bytes.Buffer
	if stdin != nil {
		if _, err := io.Copy(&program, io.LimitReader(stdin, 1<<20)); err != nil {
			return -1, err
		}
	}
	var out string
	switch {
	case bytes.Contains(program.Bytes(), []byte("systemd_state")):
		out = fixtureInventory
	case bytes.Contains(program.Bytes(), []byte("mem_total_kib")):
		out = fixtureStats
	default:
		return -1, errors.New("e2e: unexpected command on the restore fixture")
	}
	if _, err := io.WriteString(stdout, out); err != nil {
		return -1, err
	}
	return 0, nil
}

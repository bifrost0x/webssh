//go:build linux

package platform

import (
	"net"
	"path/filepath"
	"testing"
	"time"
)

func listenNotify(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func readNotify(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	buf := make([]byte, 256)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestNotifyPathSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn := listenNotify(t, path)
	t.Setenv("NOTIFY_SOCKET", path)
	sent, err := Notify(NotifyReady)
	if err != nil || !sent {
		t.Fatalf("Notify = %v, %v", sent, err)
	}
	if got := readNotify(t, conn); got != NotifyReady {
		t.Errorf("got %q", got)
	}
}

func TestNotifyAbstractSocket(t *testing.T) {
	name := "@webssh-notify-" + filepath.Base(t.TempDir())
	conn := listenNotify(t, name)
	t.Setenv("NOTIFY_SOCKET", name)
	if sent, err := Notify(NotifyStopping); err != nil || !sent {
		t.Fatalf("Notify = %v, %v", sent, err)
	}
	if got := readNotify(t, conn); got != NotifyStopping {
		t.Errorf("got %q", got)
	}
}

func TestNotifyWithoutSocket(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if sent, err := Notify(NotifyReady); sent || err != nil {
		t.Fatalf("Notify = %v, %v; want false, nil", sent, err)
	}
}

func TestNotifyRejectsUnsupportedTransport(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "vsock:2:1234")
	if _, err := Notify(NotifyReady); err == nil {
		t.Fatal("want error for vsock")
	}
}

func TestNotifyMissingListener(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
	if _, err := Notify(NotifyReady); err == nil {
		t.Fatal("want error for a missing socket")
	}
}

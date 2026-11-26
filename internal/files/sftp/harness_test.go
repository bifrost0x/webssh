package sftp

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pkgsftp "github.com/pkg/sftp"
)

// newLocal returns a backend on an in-process SFTP server (pkg/sftp's
// server on the local file system) rooted at a fresh directory.
func newLocal(t *testing.T, o Options) (*Backend, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv, cli := net.Pipe()
	server, err := pkgsftp.NewServer(srv, pkgsftp.WithServerWorkingDirectory(root))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = server.Serve(); close(done) }()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	b, err := Open(ctx, cli, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = b.Close()
		_ = srv.Close()
		<-done
	})
	return b, root
}

func put(t *testing.T, p string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

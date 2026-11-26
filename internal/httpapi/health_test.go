package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealth(t *testing.T) {
	w := newEdge(t).do(req{target: "/health"})
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"status":"ok"}` || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%d %q", w.Code, w.Body)
	}
}

func TestReady(t *testing.T) {
	dir := t.TempDir()
	stopping, maintenance := false, false
	var dbErr error
	e := newEdge(t, func(o *Options) {
		o.Readiness = Readiness{
			Stopping:    func() bool { return stopping },
			Maintenance: func() bool { return maintenance },
			Database:    pingFunc(func(context.Context) error { return dbErr }),
			DataDir:     dir,
		}
	})
	check := func(name string, code int, body string) {
		t.Helper()
		w := e.do(req{target: "/ready"})
		if w.Code != code || strings.TrimSpace(w.Body.String()) != body {
			t.Errorf("%s: %d %s, want %d %s", name, w.Code, w.Body, code, body)
		}
	}
	check("ready", 200, `{"status":"ready"}`)
	stopping = true
	check("stopping", 503, `{"status":"not_ready","failed":["runtime"]}`)
	stopping, dbErr = false, errors.New("locked")
	check("database", 503, `{"status":"not_ready","failed":["database"]}`)
	dbErr, maintenance = nil, true
	check("maintenance skips probes", 503, `{"status":"not_ready","failed":["maintenance"]}`)
}

func TestReadyDataDirProbe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	rd := newReadiness(Readiness{DataDir: dir}, newEdge(t).h.log)
	now := time.Unix(1000, 0)
	rd.now = func() time.Time { return now }
	if rd.probeDataDir() == nil {
		t.Fatal("a missing data directory passed")
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := rd.probeDataDir(); err != nil {
		t.Fatal(err)
	}
	// A success is reused within the TTL, a failure never.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := rd.probeDataDir(); err != nil {
		t.Fatalf("cached success not reused: %v", err)
	}
	now = now.Add(probeTTL)
	if rd.probeDataDir() == nil {
		t.Fatal("expired success reused")
	}
}

func TestReadyWithoutChecksIsNotReady(t *testing.T) {
	e := newEdge(t, func(o *Options) { o.Readiness = Readiness{} })
	w := e.do(req{target: "/ready"})
	if w.Code != http.StatusServiceUnavailable ||
		strings.TrimSpace(w.Body.String()) != `{"status":"not_ready","failed":["runtime","database","data_directory"]}` {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

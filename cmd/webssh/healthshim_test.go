package main

import (
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The health check commands of the Python release, byte for byte as Docker
// passes them after Compose interpolation ("$$" becomes "$").
const (
	pyReadyEnv = "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '5000') + '/ready', timeout=2).read(1)"
	pyTCP      = "import socket; s=socket.create_connection(('127.0.0.1', 5000), 2); s.close()"
	pyReadyArg = "import sys, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + sys.argv[1] + '/ready', timeout=2).read(1)"
	shLoop     = `for port in "${PORT:-5000}" 5000; do python -c "import sys, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + sys.argv[1] + '/ready', timeout=2).read(1)" "$port" && exit 0; done; exit 1`
)

func TestLegacyHealthForms(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want legacyHealth
		ok   bool
	}{
		{"ready via PORT", []string{"-c", pyReadyEnv}, legacyHealth{kind: healthReady}, true},
		{"tcp connect", []string{"-c", pyTCP}, legacyHealth{kind: healthTCP}, true},
		{"ready on argv port", []string{"-c", pyReadyArg, "8080"}, legacyHealth{kind: healthReadyPort, port: "8080"}, true},
		{"argv port missing", []string{"-c", pyReadyArg}, legacyHealth{}, false},
		{"argv port invalid", []string{"-c", pyReadyArg, "80@evil.example"}, legacyHealth{}, false},
		{"argv port out of range", []string{"-c", pyReadyArg, "65536"}, legacyHealth{}, false},
		{"extra argument", []string{"-c", pyReadyEnv, "x"}, legacyHealth{}, false},
		{"changed program", []string{"-c", pyReadyEnv + " "}, legacyHealth{}, false},
		{"other program", []string{"-c", "print(1)"}, legacyHealth{}, false},
		{"no -c", []string{pyReadyEnv}, legacyHealth{}, false},
		{"empty", nil, legacyHealth{}, false},
	}
	for _, tt := range tests {
		got, ok := parsePythonHealth(tt.args)
		if ok != tt.ok || got != tt.want {
			t.Errorf("%s: got %+v %v, want %+v %v", tt.name, got, ok, tt.want, tt.ok)
		}
	}
}

func TestShellShimRefusesEverythingElse(t *testing.T) {
	t.Parallel()
	for _, argv := range [][]string{
		{"/bin/sh"},
		{"sh", "-c", "true"},
		{"sh", "-c", "id"},
		{"/bin/sh", "-c", shLoop + " "},
		{"/bin/sh", "-c", shLoop, "extra"},
		{"/bin/sh", "-lc", shLoop},
		{"sh", "/app/entrypoint.sh"},
	} {
		code, out, e := runArgs(t, argv...)
		if code != 2 || out != "" || !strings.Contains(e, "has no shell") {
			t.Errorf("%q: %d %q %q", argv, code, out, e)
		}
	}
}

func TestPythonShimRefusesOtherPrograms(t *testing.T) {
	t.Parallel()
	for _, argv := range [][]string{
		{"python", "-c", pyReadyArg},
		{"python", "-c", pyReadyArg, "x"},
		{"python", "-c", pyTCP, "5000"},
		{"python3", "-c", pyReadyEnv + "\n"},
	} {
		code, out, e := runArgs(t, argv...)
		if code != 2 || out != "" || !strings.Contains(e, "has no Python") {
			t.Errorf("%q: %d %q %q", argv, code, out, e)
		}
	}
}

// The health check tests below set PORT and therefore do not run in
// parallel.

func TestShellShimRunsTheComposeHealthcheck(t *testing.T) {
	t.Setenv("PORT", statusServer(t, http.StatusOK))
	if code, out, e := runArgs(t, "/bin/sh", "-c", shLoop); code != 0 || out != "" {
		t.Fatalf("ready: %d %q %q", code, out, e)
	}
	t.Setenv("PORT", statusServer(t, http.StatusServiceUnavailable))
	if code, _, e := runArgs(t, "/bin/sh", "-c", shLoop); code != 1 || !strings.Contains(e, "not ready") {
		t.Fatalf("not ready: %d %q", code, e)
	}
}

func TestPythonShimRunsTheReadyHealthchecks(t *testing.T) {
	t.Setenv("PORT", statusServer(t, http.StatusOK))
	if code, _, e := runArgs(t, "python", "-c", pyReadyEnv); code != 0 {
		t.Fatalf("PORT form: %d %q", code, e)
	}
	ready := statusServer(t, http.StatusOK)
	down := statusServer(t, http.StatusServiceUnavailable)
	t.Setenv("PORT", down)
	// The argv form asks only the port it is given, as the Python program did.
	if code, _, e := runArgs(t, "python", "-c", pyReadyArg, ready); code != 0 {
		t.Fatalf("argv form, ready port: %d %q", code, e)
	}
	if code, _, e := runArgs(t, "python3", "-c", pyReadyArg, down); code != 1 || !strings.Contains(e, "not ready") {
		t.Fatalf("argv form, port not ready: %d %q", code, e)
	}
}

func TestProbeTCP(t *testing.T) {
	t.Parallel()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	if err := probeTCP(t.Context(), ln.Addr().String(), time.Second); err != nil {
		t.Fatalf("open port: %v", err)
	}
	closed, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probeTCP(t.Context(), addr, time.Second); err == nil {
		t.Fatal("closed port reported as open")
	}
}

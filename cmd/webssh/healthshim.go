package main

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"time"
)

// Compose files written for the Python image override the image's health
// check with a Python program, either directly ("CMD", "python", "-c", …)
// or through a shell loop ("CMD-SHELL", …). The Go image has neither, so
// /usr/local/bin/python and /bin/sh are links to the binary that accept
// exactly those documented programs and run the same probe. Everything
// else is refused: the links are no interpreter.
const (
	// docker-compose.yml from 3.0 to 3.2.
	pythonHealthReadyEnv = "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.getenv('PORT', '5000') + '/ready', timeout=2).read(1)"
	// docker-compose.yml before 3.0.
	pythonHealthTCP = "import socket; s=socket.create_connection(('127.0.0.1', 5000), 2); s.close()"
	// The loop body of shellHealthLoop; the port is its only argument.
	pythonHealthReadyArg = "import sys, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + sys.argv[1] + '/ready', timeout=2).read(1)"
	// docker-compose.yml since 3.3 and the HEALTHCHECK of the Python
	// image, as Docker passes it to "/bin/sh -c".
	shellHealthLoop = `for port in "${PORT:-5000}" 5000; do python -c "` + pythonHealthReadyArg + `" "$port" && exit 0; done; exit 1`

	// The timeout of every legacy program.
	legacyHealthTimeout = 2 * time.Second
)

type healthKind int

const (
	healthReady     healthKind = iota + 1 // /ready on PORT, then 5000
	healthReadyPort                       // /ready on the given port only
	healthTCP                             // TCP connect to 5000
)

type legacyHealth struct {
	kind healthKind
	port string
}

func isShellShim(argv0 string) bool {
	return filepath.Base(argv0) == "sh"
}

// parsePythonHealth recognises the argument vectors "-c <program>" and
// "-c <program> <port>" of the documented health checks.
func parsePythonHealth(args []string) (legacyHealth, bool) {
	switch {
	case len(args) == 2 && args[0] == "-c" && args[1] == pythonHealthReadyEnv:
		return legacyHealth{kind: healthReady}, true
	case len(args) == 2 && args[0] == "-c" && args[1] == pythonHealthTCP:
		return legacyHealth{kind: healthTCP}, true
	case len(args) == 3 && args[0] == "-c" && args[1] == pythonHealthReadyArg:
		if _, err := parsePort(args[2]); err != nil {
			return legacyHealth{}, false
		}
		return legacyHealth{kind: healthReadyPort, port: args[2]}, true
	}
	return legacyHealth{}, false
}

// runShellShim accepts exactly "-c <shellHealthLoop>" and runs the health
// check; it never interprets a command.
func runShellShim(ctx context.Context, args []string, s streams) int {
	if len(args) != 2 || args[0] != "-c" || args[1] != shellHealthLoop {
		write(s.stderr, "webssh: this image has no shell; use \"/app/webssh <command>\" "+
			"(\"/app/webssh help\" lists them)\n")
		return 2
	}
	return runHealthcheck(ctx, nil, s)
}

func runLegacyHealth(ctx context.Context, h legacyHealth, s streams) int {
	switch h.kind {
	case healthReadyPort:
		return probePorts(ctx, []string{h.port}, legacyHealthTimeout, s)
	case healthTCP:
		addr := net.JoinHostPort("127.0.0.1", defaultPort)
		if err := probeTCP(ctx, addr, legacyHealthTimeout); err != nil {
			write(s.stderr, fmt.Sprintf("webssh: not reachable: %v\n", err))
			return 1
		}
		return 0
	default:
		return runHealthcheck(ctx, nil, s)
	}
}

func probeTCP(ctx context.Context, addr string, timeout time.Duration) error {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return c.Close()
}

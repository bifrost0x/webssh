// Command webssh is the WebSSH server binary.
//
// It only wires packages together. The Go server is built alongside the
// Python application and replaces it in one release (see docs/adr); until
// then this binary only reports its version.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/bifrost0x/webssh/internal/buildinfo"
)

const usage = `Usage:
  webssh <command>

Commands:
  version   print the version and source revision
  help      show this help
`

// e2eCommand runs the backend of the end-to-end suite. It is set only in
// the build with the tag "e2e" (e2e.go); the release binary has no such
// command.
var e2eCommand func(args []string, stdout, stderr io.Writer) int

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one command and returns the process exit code: 0 on success,
// 1 when output cannot be written and 2 for invalid usage.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usageError(stderr, "")
	}
	switch command := args[0]; command {
	case "version":
		if len(args) > 1 {
			return usageError(stderr, "version takes no arguments")
		}
		return write(stdout, buildinfo.Read().String()+"\n")
	case "e2e":
		if e2eCommand == nil {
			return usageError(stderr, fmt.Sprintf("unknown command %q", command))
		}
		return e2eCommand(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		return write(stdout, usage)
	default:
		return usageError(stderr, fmt.Sprintf("unknown command %q", command))
	}
}

func usageError(stderr io.Writer, message string) int {
	if message != "" {
		message = "webssh: " + message + "\n\n"
	}
	write(stderr, message+usage)
	return 2
}

func write(w io.Writer, text string) int {
	if _, err := io.WriteString(w, text); err != nil {
		return 1
	}
	return 0
}

package main

import (
	"fmt"
	"io"

	"github.com/bifrost0x/webssh/internal/config"
)

// dotenvFree are the commands that never read the configuration, as in
// the Python release, where only an import of config.py loaded .env.
var dotenvFree = map[string]bool{"help": true, "-h": true, "--help": true, "version": true, "healthcheck": true, "e2e": true}

// needsDotenv reports whether the command line reads the configuration.
func needsDotenv(argv []string) bool {
	if len(argv) == 0 || isPythonShim(argv[0]) {
		return false
	}
	if isLegacyEntrypoint(argv[0]) {
		return true
	}
	return len(argv) > 1 && !dotenvFree[argv[1]]
}

// loadDotenv adds the .env file of the installation to the process
// environment before any command reads it; variables that are already set
// win. It returns false when the start must stop.
func loadDotenv(argv []string, path string, stderr io.Writer) bool {
	if !needsDotenv(argv) {
		return true
	}
	warnings, err := config.LoadDotenv(path)
	for _, w := range warnings {
		write(stderr, fmt.Sprintf("webssh: configuration: %s\n", w))
	}
	if err != nil {
		write(stderr, "webssh: "+err.Error()+"\n")
		return false
	}
	return true
}

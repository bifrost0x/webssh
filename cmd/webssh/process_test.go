package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"
)

// envProcessArgs makes the test binary run as the webssh command with the
// JSON-encoded arguments instead of running tests, so that tests can
// start the server and the administrator commands as separate processes.
const envProcessArgs = "WEBSSH_TEST_PROCESS_ARGS"

func TestMain(m *testing.M) {
	if raw := os.Getenv(envProcessArgs); raw != "" {
		var args []string
		if err := json.Unmarshal([]byte(raw), &args); err != nil {
			os.Exit(3)
		}
		s := streams{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr}
		os.Exit(dispatch(context.Background(), append([]string{"webssh"}, args...), s))
	}
	os.Exit(m.Run())
}

//go:build !e2e

package main

import (
	"bytes"
	"testing"
)

func TestReleaseBuildHasNoE2ECommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run([]string{"e2e"}, &stdout, &stderr); code != 2 || e2eCommand != nil {
		t.Fatalf("run(e2e) = %d, e2eCommand set: %t", code, e2eCommand != nil)
	}
	assertOutput(t, "stderr", stderr.String(), `unknown command "e2e"`)
}

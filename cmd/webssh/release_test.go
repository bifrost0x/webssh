//go:build !e2e

package main

import (
	"bytes"
	"context"
	"testing"
)

func TestReleaseBuildHasNoE2ECommand(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"e2e"}, streams{stdout: &stdout, stderr: &stderr}); code != 2 || e2eCommand != nil {
		t.Fatalf("run(e2e) = %d, e2eCommand set: %t", code, e2eCommand != nil)
	}
	assertOutput(t, "stderr", stderr.String(), `unknown command "e2e"`)
}

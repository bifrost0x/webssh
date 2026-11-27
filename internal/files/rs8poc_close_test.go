package files_test

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
)

func TestRS8ForeignCloseAndDescribe(t *testing.T) {
	f := newFixture(t, files.Options{})
	wantCode(t, f.reg.Close(bob, f.id), fault.SourceUnavailable)
	wantCode(t, f.reg.Close(alice2, f.id), fault.SourceUnavailable)
	if _, _, err := f.reg.Describe(bob, f.id); err == nil {
		t.Fatal("foreign describe")
	}
	if _, err := f.svc.Home(context.Background(), caller(alice), f.id); err != nil {
		t.Fatalf("owner source gone after foreign close: %v", err)
	}
}

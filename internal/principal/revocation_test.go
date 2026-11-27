package principal

import (
	"errors"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
)

func TestErrRightsReducedIsItsOwnError(t *testing.T) {
	if fault.CodeOf(ErrRightsReduced) != fault.AuthenticationNeeded {
		t.Fatalf("code %q", fault.CodeOf(ErrRightsReduced))
	}
	if errors.Is(fault.New(fault.AuthenticationNeeded, ""), ErrRightsReduced) {
		t.Fatal("every authentication_required matches ErrRightsReduced")
	}
	if !errors.Is(ErrRightsReduced, ErrRightsReduced) {
		t.Fatal("ErrRightsReduced does not match itself")
	}
}

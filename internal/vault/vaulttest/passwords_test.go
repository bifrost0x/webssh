package vaulttest_test

import (
	"context"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/vault"
	"github.com/bifrost0x/webssh/internal/vault/vaulttest"
)

// passwordSource is the interface a consumer such as internal/automation
// declares; the fake and the service satisfy it.
type passwordSource interface {
	Password(ctx context.Context, userID int64, resourceID string, t vault.Target) ([]byte, error)
}

func TestPasswordsChecksBinding(t *testing.T) {
	t.Parallel()
	var src passwordSource = &vaulttest.Passwords{}
	fake := src.(*vaulttest.Passwords)
	share := vault.Target{ID: new("smb:x"), Kind: vault.ResourceSMB, Host: new("10.0.0.5"), Share: new("Daten")}
	fake.Assign(1, "smb:x", share, []byte("s3cret"))

	got, err := src.Password(t.Context(), 1, "smb:x", share)
	if err != nil || string(got) != "s3cret" {
		t.Fatalf("Password = %q, %v", got, err)
	}
	got[0] = 'X'
	if again, _ := src.Password(t.Context(), 1, "smb:x", share); string(again) != "s3cret" {
		t.Fatal("the caller can change the stored secret")
	}
	moved := share
	moved.Host = new("10.0.0.6")
	if _, err := src.Password(t.Context(), 1, "smb:x", moved); !fault.Is(err, fault.CredentialTargetChanged) {
		t.Fatalf("changed target = %v", err)
	}
	if _, err := src.Password(t.Context(), 2, "smb:x", share); !fault.Is(err, fault.CredentialMissing) {
		t.Fatalf("other user = %v", err)
	}
	if fake.Calls() != 4 {
		t.Fatalf("calls = %d", fake.Calls())
	}
}

package vault_test

import (
	"github.com/bifrost0x/webssh/internal/ssh/client"
	"github.com/bifrost0x/webssh/internal/vault"
)

// The vault provides the dialer's key source; only this test names the
// consumer, the production code does not import it (package map).
var _ client.KeySource = (*vault.Service)(nil)

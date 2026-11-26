package realtime

import "github.com/bifrost0x/webssh/internal/principal/principaltest"

// The shared test double satisfies the revocation contract.
var _ Revocations = (*principaltest.Revocations)(nil)

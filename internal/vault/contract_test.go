package vault

import "github.com/bifrost0x/webssh/internal/principal/principaltest"

// The shared test double satisfies the step-up contract of this package.
var _ StepUp = (*principaltest.StepUp)(nil)

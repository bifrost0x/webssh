package hostops

import (
	"testing"

	"github.com/bifrost0x/webssh/internal/ssh/remotecmd"
)

// The embedded collectors stay within the cap of remotecmd.Program.
func TestEmbeddedProgramsFitTheCap(t *testing.T) {
	for name, p := range map[string]string{
		"stats": insightsStatsProgram, "diagnostics": insightsDiagnosticsProgram, "inventory": inventoryProgram,
	} {
		if len(p) == 0 || len(p) > remotecmd.MaxProgram {
			t.Errorf("%s program is %d bytes, cap %d", name, len(p), remotecmd.MaxProgram)
		}
		if _, err := remotecmd.Program(p); err != nil {
			t.Errorf("%s program refused: %v", name, err)
		}
	}
}

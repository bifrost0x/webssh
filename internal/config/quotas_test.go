package config

import "testing"

func TestQuotaLimits(t *testing.T) {
	c, _ := mustLoad(t, nil)
	want := map[string]QuotaLimit{
		"ssh_session": {10, 5}, "quick_connection": {12, 3}, "transfer": {8, 2},
		"temp_bytes": {1 << 30, 512 << 20}, "background_job": {4, 1},
	}
	if len(c.Quotas) != len(want) {
		t.Fatalf("quotas %v", c.Quotas)
	}
	for k, v := range want {
		if c.Quotas[k] != v {
			t.Errorf("%s: %+v, want %+v", k, c.Quotas[k], v)
		}
	}
	c, _ = mustLoad(t, map[string]string{
		"QUOTA_TRANSFER_GLOBAL": "99999999999999999999999", "QUOTA_TRANSFER_PER_USER": "99999999999999999999998",
		"QUOTA_TEMP_BYTES_GLOBAL": "99999999999999999999999", "QUOTA_TEMP_BYTES_PER_USER": "99999999999999999999999",
	})
	const top = 1<<63 - 1
	if got := c.Quotas["transfer"]; got != (QuotaLimit{top, top - 1}) {
		t.Errorf("saturated transfer %+v", got)
	}
	if got := c.Quotas["temp_bytes"]; got != (QuotaLimit{top, top}) {
		t.Errorf("saturated temp_bytes %+v", got)
	}
}

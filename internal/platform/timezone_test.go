package platform

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	_ "time/tzdata" // the zone database the binary embeds
)

func TestCheckTimeZone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		tz      string
		set     bool
		wantErr bool
	}{
		{name: "unset", set: false},
		{name: "unset ignores value", tz: "Invalid/Zone", set: false},
		{name: "empty means UTC", tz: "", set: true},
		{name: "UTC", tz: "UTC", set: true},
		{name: "colon only", tz: ":", set: true},
		{name: "IANA name", tz: "Europe/Berlin", set: true},
		{name: "IANA name with colon", tz: ":America/New_York", set: true},
		{name: "half-hour offset", tz: "Asia/Kolkata", set: true},
		{name: "Etc zone", tz: "Etc/UTC", set: true},
		{name: "misspelled", tz: "Europe/Berlinn", set: true, wantErr: true},
		{name: "invalid", tz: "Invalid/Zone", set: true, wantErr: true},
		{name: "POSIX rule", tz: "CET-1CEST,M3.5.0,M10.5.0/3", set: true, wantErr: true},
		{name: "Local", tz: "Local", set: true, wantErr: true},
		{name: "path traversal", tz: "../../etc/passwd", set: true, wantErr: true},
		{name: "missing zone file", tz: "/nonexistent/zone", set: true, wantErr: true},
		{name: "lowercase utc", tz: "utc", set: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := CheckTimeZone(tt.tz, tt.set)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckTimeZone(%q, %v) = %v, want error %v", tt.tz, tt.set, err, tt.wantErr)
			}
		})
	}
}

func TestCheckTimeZoneFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad")
	if err := os.WriteFile(bad, []byte("not a zone file"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckTimeZone(bad, true); err == nil {
		t.Error("want an error for a file that is not a zone file")
	}
	if err := CheckTimeZone(dir, true); err == nil {
		t.Error("want an error for a directory")
	}
	if _, err := os.Stat("/usr/share/zoneinfo/Europe/Berlin"); err == nil {
		if err := CheckTimeZone("/usr/share/zoneinfo/Europe/Berlin", true); err != nil {
			t.Errorf("zone file: %v", err)
		}
		if err := CheckTimeZone(":/usr/share/zoneinfo/Europe/Berlin", true); err != nil {
			t.Errorf("zone file with colon: %v", err)
		}
	}
}

// The check must agree with time.Local for every value it accepts or
// rejects; a value it accepts must not leave the process in UTC.
func FuzzCheckTimeZone(f *testing.F) {
	for _, seed := range []string{"", ":", "UTC", "Europe/Berlin", ":Asia/Kolkata", "Invalid/Zone", "Local", "/etc/localtime", "../x", "CET-1CEST"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, tz string) {
		err := CheckTimeZone(tz, true)
		if err != nil || len(tz) == 0 || tz[0] == '/' || (tz[0] == ':' && len(tz) > 1 && tz[1] == '/') {
			return
		}
		name := tz
		if name[0] == ':' {
			name = name[1:]
		}
		if name == "" || name == "UTC" {
			return
		}
		if _, loadErr := time.LoadLocation(name); loadErr != nil {
			t.Errorf("CheckTimeZone(%q) accepted a zone time.LoadLocation rejects: %v", tz, loadErr)
		}
	})
}

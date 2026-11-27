package hosts

import (
	json "encoding/json/v2"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The oracle is recorded from app/host_platform.py by
// testdata/platform_oracle.py.

type platformOracle struct {
	IdentityScript    string `json:"identity_script"`
	MaintenanceScript string `json:"maintenance_command"`
	RebootHintScript  string `json:"reboot_hint_command"`
	Catalog           struct {
		Services       []string          `json:"services"`
		Priority       []string          `json:"priority"`
		Infrastructure []string          `json:"infrastructure"`
		MaxServices    int               `json:"max_services"`
		NonPOSIX       []string          `json:"non_posix"`
		OSIDPlatforms  map[string]string `json:"os_id_platforms"`
		Families       map[string]string `json:"families"`
		Markers        [][2]string       `json:"markers"`
		Kernels        map[string]string `json:"kernels"`
		Virt           map[string]string `json:"virt"`
		Units          [][2]string       `json:"units"`
		Templates      [][2]string       `json:"templates"`
		Paths          [][2]string       `json:"paths"`
		Snaps          [][2]string       `json:"snaps"`
		Platforms      []string          `json:"platforms"`
	} `json:"catalog"`
	Identity []struct {
		Text  string          `json:"text"`
		OK    *identityResult `json:"ok"`
		Error bool            `json:"error"`
	} `json:"identity"`
	Deadline []struct {
		Output []int  `json:"output"`
		Answer string `json:"answer"`
	} `json:"deadline"`
	Maintenance []struct {
		Text string `json:"text"`
		OK   *struct {
			RebootRequired  *bool `json:"reboot_required"`
			Updates         *int  `json:"updates"`
			SecurityUpdates *int  `json:"security_updates"`
		} `json:"ok"`
		Error bool `json:"error"`
	} `json:"maintenance"`
	Reboot []struct {
		Text  string `json:"text"`
		OK    *bool  `json:"ok"`
		Error bool   `json:"error"`
	} `json:"reboot"`
}

// identityResult is the parse_identity dict.
type identityResult struct {
	State           string   `json:"state"`
	Platform        *string  `json:"platform"`
	Family          *string  `json:"family"`
	OSID            *string  `json:"os_id"`
	OSVersion       *string  `json:"os_version"`
	Virt            *string  `json:"virt"`
	Graphical       *bool    `json:"graphical"`
	Guests          *int     `json:"guests"`
	Services        []string `json:"services"`
	ContainerAccess *string  `json:"container_access"`
}

func opt(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func resultOf(id Identity) identityResult {
	return identityResult{State: id.State, Platform: opt(id.Platform), Family: opt(id.Family), OSID: opt(id.OSID),
		OSVersion: opt(id.OSVersion), Virt: opt(id.Virt), Graphical: id.Graphical, Guests: id.Guests,
		Services: id.Services, ContainerAccess: opt(id.ContainerAccess)}
}

func readPlatformOracle(t *testing.T) platformOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/platform_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o platformOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestProbeScriptsMatchPython(t *testing.T) {
	o := readPlatformOracle(t)
	if IdentityScript != o.IdentityScript {
		t.Errorf("identity script differs from IDENTITY_SCRIPT")
	}
	if MaintenanceScript != o.MaintenanceScript || RebootHintScript != o.RebootHintScript {
		t.Errorf("maintenance scripts differ from Python")
	}
}

func setOf(items []string) map[string]bool { return set(items...) }

func mapOf(pairs [][2]string) map[string]string {
	m := map[string]string{}
	for _, p := range pairs {
		m[p[0]] = p[1]
	}
	return m
}

func TestIdentityCatalogMatchesPython(t *testing.T) {
	c := readPlatformOracle(t).Catalog
	checks := []struct {
		name      string
		got, want any
	}{
		{"services", services, setOf(c.Services)},
		{"priority", priorityServices, setOf(c.Priority)},
		{"infrastructure", infrastructureServices, setOf(c.Infrastructure)},
		{"max", maxServices, c.MaxServices},
		{"nonposix", nonPOSIXPlatforms, setOf(c.NonPOSIX)},
		{"platforms", platforms, setOf(c.Platforms)},
		{"osid", osIDPlatforms, c.OSIDPlatforms},
		{"families", familyOf, c.Families},
		{"markers", markerPlatforms, c.Markers},
		{"kernels", kernelPlatforms, c.Kernels},
		{"virt", virtMap, c.Virt},
		{"units", serviceUnits, c.Units},
		{"templates", serviceUnitTemplates, c.Templates},
		{"paths", servicePaths, c.Paths},
		{"snaps", serviceSnaps, c.Snaps},
	}
	for _, ch := range checks {
		if !reflect.DeepEqual(ch.got, ch.want) {
			t.Errorf("%s: catalog differs from Python", ch.name)
		}
	}
	if got, want := slices.Sorted(maps.Values(mapOf(serviceUnits))), c.Services; len(got) == 0 || len(want) == 0 {
		t.Fatal("empty catalog")
	}
	for _, s := range slices.Concat(slices.Collect(maps.Values(mapOf(serviceUnits))), slices.Collect(maps.Values(mapOf(serviceSnaps)))) {
		if !services[s] {
			t.Errorf("%s is not a service of the catalog", s)
		}
	}
}

func TestParseIdentityMatchesPython(t *testing.T) {
	o := readPlatformOracle(t)
	if len(o.Identity) < 500 {
		t.Fatalf("only %d identity cases", len(o.Identity))
	}
	for i, c := range o.Identity {
		got, err := ParseIdentity(c.Text)
		if c.Error {
			if err == nil {
				t.Errorf("case %d %q: no error, Python refused it", i, short(c.Text))
			}
			continue
		}
		if err != nil {
			t.Errorf("case %d %q: %v", i, short(c.Text), err)
			continue
		}
		if r := resultOf(got); !reflect.DeepEqual(r, *c.OK) {
			a, _ := json.Marshal(r)
			b, _ := json.Marshal(c.OK)
			t.Errorf("case %d %q:\n go     %s\n python %s", i, short(c.Text), a, b)
		}
	}
}

func short(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

func bytesOf(ints []int) []byte {
	b := make([]byte, len(ints))
	for i, v := range ints {
		b[i] = byte(v)
	}
	return b
}

func TestIdentityAtDeadlineMatchesPython(t *testing.T) {
	for i, c := range readPlatformOracle(t).Deadline {
		out := bytesOf(c.Output)
		if got := identityAtDeadline(out); got != c.Answer {
			t.Errorf("case %d %q: %s, Python %s", i, short(string(out)), got, c.Answer)
		}
	}
}

func TestParseMaintenanceMatchesPython(t *testing.T) {
	for i, c := range readPlatformOracle(t).Maintenance {
		got, err := ParseMaintenance(c.Text)
		if c.Error != (err != nil) {
			t.Errorf("case %d %q: error %v, Python error %v", i, short(c.Text), err, c.Error)
			continue
		}
		if c.OK != nil && (!reflect.DeepEqual(got.RebootRequired, c.OK.RebootRequired) ||
			!reflect.DeepEqual(got.Updates, c.OK.Updates) || !reflect.DeepEqual(got.SecurityUpdates, c.OK.SecurityUpdates)) {
			t.Errorf("case %d %q: %+v, Python %+v", i, short(c.Text), got, *c.OK)
		}
	}
}

func TestParseRebootHintMatchesPython(t *testing.T) {
	for i, c := range readPlatformOracle(t).Reboot {
		got, err := ParseRebootHint(c.Text)
		if c.Error != (err != nil) || (c.OK != nil && got != *c.OK) {
			t.Errorf("case %d %q: %v %v, Python %v %v", i, c.Text, got, err, c.OK, c.Error)
		}
	}
}

func TestIdentityScriptRefusesShellSyntax(t *testing.T) {
	for _, bad := range [][2]string{{"a;b", "x"}, {"-x", "x"}, {"in", "x"}, {"a b", "x"}, {"$(id)", "x"}, {"a", "'q'"}} {
		if _, err := identityScript([][2]string{bad}, nil, nil, nil); err == nil {
			t.Errorf("unit %q accepted", bad)
		}
	}
	if _, err := identityScript(nil, nil, [][2]string{{"relative/path", "nginx"}}, nil); err == nil {
		t.Error("relative path accepted")
	}
	if !strings.Contains(IdentityScript, "nginx|apache2|httpd") || len(IdentityScript) > 8192 {
		t.Errorf("unexpected identity script of %d bytes", len(IdentityScript))
	}
}

func FuzzParseIdentity(f *testing.F) {
	for _, s := range []string{"kernel=Linux\nID=debian\n", "ID=x\nkernel=Darwin\nimage=nginx:1\nengine=docker:ok\n", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		id, err := ParseIdentity(text)
		if err != nil {
			return
		}
		if id.State != StateDetected && id.State != StateUnavailable {
			t.Fatalf("state %q", id.State)
		}
		if id.Platform != "" && !platforms[id.Platform] || len(id.Services) > maxServices {
			t.Fatalf("value outside the catalog: %+v", id)
		}
		for _, s := range id.Services {
			if !services[s] {
				t.Fatalf("service %q outside the catalog", s)
			}
		}
		_ = identityAtDeadline([]byte(text))
		_, _ = ParseMaintenance(text)
	})
}

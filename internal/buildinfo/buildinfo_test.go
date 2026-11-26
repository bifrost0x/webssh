package buildinfo

import (
	"runtime/debug"
	"testing"
)

const (
	testRevision  = "34eb151c0ffee34eb151c0ffee34eb151c0ffee3"
	otherRevision = "abc1234def5678abc1234def5678abc1234def56"
)

func TestResolve(t *testing.T) {
	t.Parallel()
	vcs := func(revision, modified string) *debug.BuildInfo {
		return &debug.BuildInfo{
			GoVersion: "go1.27.4",
			// A v2+ tag without a major-version suffix in the module path
			// yields a pseudo-version; it must never be shown as a release.
			Main: debug.Module{Version: "v3.3.1-0.20261126050155-34eb15138ad6+incompatible"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: revision},
				{Key: "vcs.modified", Value: modified},
			},
		}
	}
	tests := []struct {
		name           string
		linkedVersion  string
		linkedRevision string
		bi             *debug.BuildInfo
		ok             bool
		want           Info
	}{
		{
			name: "no build information and no linker values",
			want: Info{Version: develVersion},
		},
		{
			name:          "release build with linker values",
			linkedVersion: "3.4.0", linkedRevision: testRevision,
			bi: vcs(otherRevision, "false"), ok: true,
			want: Info{Version: "3.4.0", Revision: testRevision, GoVersion: "go1.27.4"},
		},
		{
			name:          "release candidate version",
			linkedVersion: "3.4.0-rc.1",
			bi:            vcs(testRevision, "false"), ok: true,
			want: Info{Version: "3.4.0-rc.1", Revision: testRevision, GoVersion: "go1.27.4"},
		},
		{
			name: "development build falls back to VCS stamping",
			bi:   vcs(testRevision, "true"), ok: true,
			want: Info{Version: develVersion, Revision: testRevision, Modified: true, GoVersion: "go1.27.4"},
		},
		{
			name:          "malformed linker version is not shown",
			linkedVersion: "v3.4.0; echo",
			bi:            vcs(testRevision, "false"), ok: true,
			want: Info{Version: develVersion, Revision: testRevision, GoVersion: "go1.27.4"},
		},
		{
			name:           "malformed linker revision falls back to VCS",
			linkedRevision: "34eb151",
			bi:             vcs(testRevision, "false"), ok: true,
			want: Info{Version: develVersion, Revision: testRevision, GoVersion: "go1.27.4"},
		},
		{
			name: "malformed VCS revision is dropped",
			bi:   vcs("34EB151; rm -rf", "false"), ok: true,
			want: Info{Version: develVersion, GoVersion: "go1.27.4"},
		},
		{
			name:           "linker revision without build information",
			linkedRevision: testRevision,
			want:           Info{Version: develVersion, Revision: testRevision},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := resolve(tt.linkedVersion, tt.linkedRevision, tt.bi, tt.ok); got != tt.want {
				t.Errorf("resolve() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestInfoString(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		info Info
		want string
	}{
		{name: "release", info: Info{Version: "3.4.0", Revision: testRevision}, want: "3.4.0 (34eb151)"},
		{name: "no revision", info: Info{Version: "3.4.0"}, want: "3.4.0"},
		{name: "modified development build", info: Info{Version: develVersion, Revision: testRevision, Modified: true}, want: "dev (34eb151, modified)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.info.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReadReportsRunningBinary(t *testing.T) {
	t.Parallel()
	info := Read()
	if info.Version == "" || info.GoVersion == "" || info.Platform == "" {
		t.Fatalf("Read() = %+v, want version, Go version and platform", info)
	}
}

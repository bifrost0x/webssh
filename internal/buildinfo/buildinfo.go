// Package buildinfo reports the release version and source revision of the
// running binary.
//
// Release builds set both values with the linker:
//
//	go build -ldflags "-X github.com/bifrost0x/webssh/internal/buildinfo.version=3.4.0
//	  -X github.com/bifrost0x/webssh/internal/buildinfo.revision=<full commit id>"
//
// The module version of the toolchain is deliberately not used: release tags
// are v3.x while the module path has no major-version suffix, so the
// toolchain reports pseudo-versions. Without linker values a build reports
// "dev" and the revision from the toolchain's VCS stamping, if any. Docker
// builds have no .git in their context and must pass the revision.
package buildinfo

import (
	"regexp"
	"runtime"
	"runtime/debug"
)

// develVersion is reported when no valid release version was linked in.
const develVersion = "dev"

// Set with -ldflags -X for release builds.
var (
	version  string
	revision string
)

var (
	// Release versions have the form of app/version.py, optionally with a
	// pre-release suffix such as "-rc.1".
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)
	// Only full Git commit ids are reported, like the Python application,
	// so a stray or truncated value never reaches logs or the UI.
	revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Info describes the running binary.
type Info struct {
	Version   string // release version, or "dev"
	Revision  string // full commit id, empty when unknown
	Modified  bool   // a development build from a checkout with local changes
	GoVersion string
	Platform  string // GOOS/GOARCH
}

// Read returns the build information of the running binary.
func Read() Info {
	bi, ok := debug.ReadBuildInfo()
	info := resolve(version, revision, bi, ok)
	if info.GoVersion == "" {
		info.GoVersion = runtime.Version()
	}
	info.Platform = runtime.GOOS + "/" + runtime.GOARCH
	return info
}

// resolve combines the linker values with the toolchain's build
// information. Valid linker values take precedence.
func resolve(linkedVersion, linkedRevision string, bi *debug.BuildInfo, ok bool) Info {
	info := Info{Version: develVersion}
	if versionPattern.MatchString(linkedVersion) {
		info.Version = linkedVersion
	}
	if revisionPattern.MatchString(linkedRevision) {
		info.Revision = linkedRevision
	}
	if !ok || bi == nil {
		return info
	}
	info.GoVersion = bi.GoVersion
	if info.Revision != "" {
		return info
	}
	for _, setting := range bi.Settings {
		switch setting.Key {
		case "vcs.revision":
			if revisionPattern.MatchString(setting.Value) {
				info.Revision = setting.Value
			}
		case "vcs.modified":
			info.Modified = setting.Value == "true"
		}
	}
	return info
}

// String formats the version like the Python application, for example
// "3.4.0 (abc1234)".
func (i Info) String() string {
	switch {
	case i.Revision != "" && i.Modified:
		return i.Version + " (" + i.Revision[:7] + ", modified)"
	case i.Revision != "":
		return i.Version + " (" + i.Revision[:7] + ")"
	}
	return i.Version
}

package platform

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// maxZoneFileSize bounds reading a zone file named by an absolute TZ path,
// as the time package does.
const maxZoneFileSize = 10 << 20

// errUnknownZone is the cause for TZ values the time package cannot load.
var errUnknownZone = errors.New("unknown time zone")

// CheckTimeZone reports whether the TZ value set by the operator selects a
// time zone. The time package falls back to UTC without any message when it
// cannot load the zone, for example for a misspelled name or a POSIX rule
// such as "CET-1CEST", which the C library accepts. The rules follow
// time.Local: an unset TZ uses /etc/localtime, an empty TZ and "UTC" mean
// UTC, a leading ':' is ignored and an absolute path names a zone file.
// Names are resolved with the zone database built into the binary.
func CheckTimeZone(tz string, set bool) error {
	if !set {
		return nil
	}
	name := strings.TrimPrefix(tz, ":")
	if name == "" || name == "UTC" {
		return nil
	}
	var err error
	switch {
	case strings.HasPrefix(name, "/"):
		err = loadZoneFile(name)
	case name == "Local":
		// time.LoadLocation maps "Local" to time.Local, but TZ=Local
		// selects no zone.
		err = errUnknownZone
	default:
		_, err = time.LoadLocation(name)
	}
	if err != nil {
		return fmt.Errorf("TZ=%q does not name a time zone, times are in UTC: %w", tz, err)
	}
	return nil
}

func loadZoneFile(path string) error {
	f, err := os.Open(path) // #nosec G304 -- the operator names the zone file in TZ
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(f, maxZoneFileSize+1))
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if len(data) > maxZoneFileSize {
		return fmt.Errorf("zone file larger than %d bytes", maxZoneFileSize)
	}
	_, err = time.LoadLocationFromTZData(path, data)
	return err
}

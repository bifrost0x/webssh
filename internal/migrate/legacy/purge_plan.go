package legacy

import (
	"errors"
	"strings"
)

// ErrPurgeAborted is returned when PurgeOptions.Confirm declines; nothing
// was written or removed.
var ErrPurgeAborted = errors.New("legacy: purge aborted")

// PurgePlan is what a purge is about to do, for the confirmation.
type PurgePlan struct {
	// Files counts the legacy files the purge removes.
	Files int
	// Kept are the paths the migration left in place (kept_in_place of
	// the report) that hold files the purge removes; Files of each is the
	// number of those files. Go has not taken them over, so they go into
	// the verified backup.
	Kept []KeptPath
	// KeptFiles are those files, relative to DATA_DIR in POSIX form.
	KeptFiles []string
	// SkipBackup is --skip-backup.
	SkipBackup bool
}

// planPurge lists the files a purge removes and which of them lie below a
// path the migration kept in place. logs/ and go/ never belong to the
// list, so entries there (E34) do not appear.
func planPurge(rep Report, files []string, skipBackup bool) PurgePlan {
	p := PurgePlan{Files: len(files), SkipBackup: skipBackup}
	taken := map[string]bool{}
	for _, k := range rep.KeptInPlace {
		n := 0
		for _, f := range files {
			if f == k.Path || strings.HasPrefix(f, strings.TrimSuffix(k.Path, "/")+"/") {
				n++
				if !taken[f] {
					taken[f] = true
					p.KeptFiles = append(p.KeptFiles, f)
				}
			}
		}
		if n > 0 {
			k.Files = n
			p.Kept = append(p.Kept, k)
		}
	}
	return p
}

// refuseUnsavedKept refuses --skip-backup while legacy files Go did not
// take over would be removed: they exist nowhere else.
func refuseUnsavedKept(state State, p PurgePlan) error {
	if !p.SkipBackup || len(p.KeptFiles) == 0 {
		return nil
	}
	paths := make([]string, 0, len(p.Kept))
	for _, k := range p.Kept {
		paths = append(paths, k.Path)
	}
	return stop(state, CodePurgeRefused, "the legacy data holds files the migration kept in place ("+strings.Join(paths, ", ")+
		"); Go has no copy of them, so a purge without a backup would lose them. Run the purge with a backup", nil)
}

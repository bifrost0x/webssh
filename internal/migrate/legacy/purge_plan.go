package legacy

import (
	"errors"
	"fmt"
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
	// Unclaimed are files the purge removes that are no 3.3 data the
	// migration took over (pythonDataFile) and lie below no kept path:
	// the operator's own files or left-overs. They go into the verified
	// backup as well.
	Unclaimed []string
	// KeptFiles are the files of Kept and Unclaimed, relative to DATA_DIR
	// in POSIX form; they go into the backup.
	KeptFiles []string
	// Changed are recorded files that differ from the migration record
	// in S5 (written since the migration); the purge leaves them in
	// place.
	Changed []string
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
	for _, f := range files {
		if !taken[f] && !pythonDataFile(f) {
			p.Unclaimed = append(p.Unclaimed, f)
			p.KeptFiles = append(p.KeptFiles, f)
		}
	}
	return p
}

// maxNamedUnclaimed bounds the unclaimed paths a refusal names.
const maxNamedUnclaimed = 10

// refuseUnsavedKept refuses --skip-backup while files Go did not take
// over would be removed: they exist nowhere else.
func refuseUnsavedKept(state State, p PurgePlan) error {
	if !p.SkipBackup || len(p.KeptFiles) == 0 {
		return nil
	}
	paths := make([]string, 0, len(p.Kept)+maxNamedUnclaimed+1)
	for _, k := range p.Kept {
		paths = append(paths, k.Path)
	}
	for i, f := range p.Unclaimed {
		if i == maxNamedUnclaimed {
			paths = append(paths, fmt.Sprintf("and %d more", len(p.Unclaimed)-i))
			break
		}
		paths = append(paths, f)
	}
	return stop(state, CodePurgeRefused, "the data directory holds files Go did not take over ("+strings.Join(paths, ", ")+
		"); Go has no copy of them, so a purge without a backup would lose them. Run the purge with a backup", nil)
}

// withoutChanged drops the files that are gone and those whose size or
// SHA-256 differs from the migration record (state S5, where the digest
// is not compared): the latter were written after the migration and are
// not the recorded 3.3 data.
func withoutChanged(dataDir string, rec *Record, files []string) (kept, changed []string, err error) {
	now, err := scanSource(dataDir, rec.Listing, rec.ScannedAt)
	if err != nil {
		return nil, nil, err
	}
	recorded := make(map[string]FileStat, len(rec.Listing))
	for _, f := range rec.Listing {
		recorded[f.Path] = f
	}
	current := make(map[string]FileStat, len(now.Files))
	for _, f := range now.Files {
		current[f.Path] = f
	}
	for _, f := range files {
		c, exists := current[f]
		r := recorded[f]
		switch {
		case !exists: // already gone
		case c.Size != r.Size || c.SHA256 != r.SHA256:
			changed = append(changed, f)
		default:
			kept = append(kept, f)
		}
	}
	return kept, changed, nil
}

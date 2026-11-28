package legacy

import (
	"regexp"
	"slices"
)

// pythonTopFiles are the 3.3 data files directly in DATA_DIR that the
// migration reads. secret_key is never removed (purgeList).
var pythonTopFiles = []string{
	"app.db", "app.db-wal", "app.db-shm", "app.db-journal", "app_settings.json", "known_hosts", "session_epoch",
	"recovery-check.json", "restore-status.json", "system_commands.json",
}

// pythonUserFiles are the stores of a 3.3 account directory
// (users/user_<id>/) that the migration reads.
var pythonUserFiles = []string{
	"automation.json", "automation-runs.json", "automation-vault.json", "command_sets.json", "commands.json",
	"credentials.json", "host_context.json", "jump_hosts.json", "keys.json", "known_hosts", "profiles.json",
	"settings.json", "smb_shares.json", "socks_proxies.json",
}

var (
	pythonUserFile = regexp.MustCompile(`^users/user_[0-9]+/([^/]+)$`)
	pythonUserKey  = regexp.MustCompile(`^users/user_[0-9]+/keys/[^/]+$`)
)

// pythonDataFile reports whether path (relative to DATA_DIR, POSIX form)
// is a file of the 3.3 layout that the migration takes over. A file the
// purge would remove that is none of them is the operator's own data or
// a left-over (a backup copy, an export, a certificate): the purge names
// it and puts it into its backup. The list errs on the side of naming a
// file: a 3.3 file missing here is only backed up as well.
func pythonDataFile(path string) bool {
	if slices.Contains(pythonTopFiles, path) || pythonUserKey.MatchString(path) {
		return true
	}
	m := pythonUserFile.FindStringSubmatch(path)
	return m != nil && slices.Contains(pythonUserFiles, m[1])
}

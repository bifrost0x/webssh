package hostops

// contextTableSQL holds the rest of a host context (C-CONN-13, E28): the
// favourite directories and the command-set references of one saved host,
// with the revision the host context had in the Python release. The notes
// of the same context live in hostops_notes with the same revision (D-11).
// A row exists once a context was saved or migrated, even when it is
// empty, so the revision continues.
const contextTableSQL = `CREATE TABLE hostops_host_context (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	profile_id TEXT NOT NULL CHECK (length(profile_id) BETWEEN 1 AND 128),
	directories TEXT NOT NULL CHECK (json_valid(directories) AND json_type(directories) = 'array'),
	command_sets TEXT NOT NULL CHECK (json_valid(command_sets) AND json_type(command_sets) = 'array'),
	revision INTEGER NOT NULL CHECK (revision >= 1),
	PRIMARY KEY (user_id, profile_id)
) STRICT`

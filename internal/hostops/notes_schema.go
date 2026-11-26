package hostops

// notesTableSQL creates the one notes model (D-11, migration spec 4.5,
// E28 and A05): a note belongs to one saved host of the user, or to no
// host (profile_id NULL, the notepad of the workspace). An empty note has
// no row. The revision counts saves; a host note continues the revision
// of its legacy host context.
const notesTableSQL = `CREATE TABLE hostops_notes (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	profile_id TEXT CHECK (profile_id IS NULL OR length(profile_id) BETWEEN 1 AND 128),
	body TEXT NOT NULL CHECK (body <> ''),
	revision INTEGER NOT NULL CHECK (revision >= 0)
) STRICT;
CREATE UNIQUE INDEX hostops_notes_host ON hostops_notes (user_id, profile_id) WHERE profile_id IS NOT NULL;
CREATE UNIQUE INDEX hostops_notes_none ON hostops_notes (user_id) WHERE profile_id IS NULL`

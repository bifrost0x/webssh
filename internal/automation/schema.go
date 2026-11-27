package automation

import "github.com/bifrost0x/webssh/internal/store"

// Schema is the automation schema (owner "automation").
//
// automation_runbooks and automation_runbook_steps hold the runbook
// library of a user (automation.json of the Python release); seq keeps
// the order of the library, which a save changes as in Python: the saved
// runbook moves to the end. automation_runs holds the run history
// (automation-runs.json): one JSON document per run, with the member
// order the Python release wrote, so an export of a migrated run is the
// same text. seq orders the history, the highest first.
func Schema() store.Schema {
	return store.Schema{Owner: "automation", Migrations: []store.Migration{{
		Version: 1,
		SQL: `CREATE TABLE automation_runbooks (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	name TEXT NOT NULL,
	stop_on_error INTEGER NOT NULL CHECK (stop_on_error IN (0, 1)),
	PRIMARY KEY (user_id, id),
	UNIQUE (user_id, seq)
) STRICT;
CREATE TABLE automation_runbook_steps (
	user_id INTEGER NOT NULL,
	runbook_id TEXT NOT NULL,
	position INTEGER NOT NULL CHECK (position >= 0),
	name TEXT NOT NULL,
	command TEXT NOT NULL,
	timeout INTEGER NOT NULL,
	sudo INTEGER NOT NULL CHECK (sudo IN (0, 1)),
	PRIMARY KEY (user_id, runbook_id, position),
	FOREIGN KEY (user_id, runbook_id) REFERENCES automation_runbooks (user_id, id) ON DELETE CASCADE
) STRICT;
CREATE TABLE automation_runs (
	user_id INTEGER NOT NULL CHECK (user_id > 0),
	id TEXT NOT NULL,
	seq INTEGER NOT NULL,
	document TEXT NOT NULL,
	PRIMARY KEY (user_id, id),
	UNIQUE (user_id, seq)
) STRICT`,
	}}}
}

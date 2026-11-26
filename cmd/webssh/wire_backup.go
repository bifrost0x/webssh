package main

import (
	"github.com/bifrost0x/webssh/internal/auth/stepup"
	"github.com/bifrost0x/webssh/internal/backup"
)

// backupArea wires the area "backup" (OP1): backup and restore (internal/backup, restore of Python backups through internal/migrate/legacy).
// OP1 fills in the hooks; no other package edits this file.
func backupArea() extension {
	return extension{name: "backup"}
}

// The providers that exist already satisfy the consumer interfaces of
// the area.
var (
	_ backup.StepUp = (*stepup.Service)(nil)
)

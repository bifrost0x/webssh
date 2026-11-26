package commands

import (
	"context"
	"time"
)

// Command is a command of the library. Built-in templates have IDs
// "sys-NNN" and System set; their names and descriptions are translated in
// the page (static/i18n/commands).
type Command struct {
	ID          string
	Name        string
	Command     string
	Parameters  string // appended to Command for library steps unless overridden
	Description string
	Category    string   // "custom" for new user commands
	OS          []string // linux, macos, bsd, windows, all; empty means all
	System      bool
	CreatedAt   string // kept as stored (naive UTC ISO in the Python release)
}

// StepType is the kind of a command set step.
type StepType string

const (
	StepInline  StepType = "inline"  // Command is the text
	StepLibrary StepType = "library" // CommandID refers to a Command
	StepArgv    StepType = "argv"    // Argv with {{name}} placeholders; parameterised sets only
)

// Step is one step of a command set.
type Step struct {
	Type      StepType
	Command   string
	CommandID string
	// Override replaces the command's Parameters for this step; nil keeps
	// them.
	Override *string
	Argv     []string
}

// Set is a command set. A set with Parameters has only argv steps and is
// resolved with values given at launch; it cannot be a startup command.
type Set struct {
	ID          string
	Name        string // unique case-insensitively
	Description string
	UseSudo     bool
	Steps       []Step
	Parameters  []string // names, [A-Za-z_][A-Za-z0-9_]{0,31}
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Limits of commands and sets (app/command_storage_policy.py,
// app/command_parameters.py; configurable values are defaults).
const (
	MaxCommandNameBytes    = 512
	MaxCommandBytes        = 16 << 10
	MaxOSEntries           = 16 // COMMAND_OS_MAX_ENTRIES
	MaxSetNameRunes        = 128
	MaxCommands            = 500 // COMMAND_MAX_RECORDS
	MaxSets                = 500 // COMMAND_SET_MAX_RECORDS
	MaxSetSteps            = 64  // COMMAND_SET_MAX_STEPS
	MaxParameters          = 20
	MaxArgvSteps           = 50
	MaxArgvArgs            = 64
	MaxArgRunes            = 1024
	MaxTemplateRunes       = 4096
	MaxResolvedRunes       = 4096 // normalize_startup_commands
	MaxReferencedSetsShown = 20
)

// Usage is one record that refers to a command or a set; delete answers
// fault.InUse with the usages in details.
type Usage struct {
	ID   string
	Name string
	Type string // "profile", "command_set"
}

// References reports the records of other capabilities that refer to a
// set or a command (provided in cmd/webssh by an adapter over
// internal/hosts: profiles with command_set_id or command_id). Host
// context references do not block a delete; they are checked when the
// host context is saved.
type References interface {
	SetUsages(ctx context.Context, userID int64, setID string) ([]Usage, error)
	CommandUsages(ctx context.Context, userID int64, commandID string) ([]Usage, error)
}

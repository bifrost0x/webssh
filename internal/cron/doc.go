// Package cron parses the five-field cron expressions of automation
// schedules and computes the next run in an IANA time zone (tier C). The
// grammar and the time rules are those of app/automation_cron.py; the
// contract is described in docs/architecture/m2-contracts.md.
package cron

import "time"

// Limits of an expression and a zone name, and the search horizon of the
// next run.
const (
	MaxExprBytes = 128
	MaxZoneBytes = 128
	Horizon      = (366*5 + 1) * 24 * time.Hour
)

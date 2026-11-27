// Package hostops holds what WebSSH knows and does around saved hosts:
// server operations, discovery and the reachability check behind their
// permission, runtime inventory, host context, session insights and notes
// (one model: a note belongs to a saved host or to none, D-11).
//
// Server operations (http_operations.go, ops_*.go), session insights, the
// runtime inventory and the Herdr snapshot (diagnostics.go, herdr*.go)
// run fixed commands through internal/ssh/remotecmd on a separate channel
// of the caller's terminal session; values from requests reach a command
// line only after an allowlist pattern, and remote output is parsed as
// untrusted text. Notes live in notes*.go, the overview in overview*.go.
package hostops

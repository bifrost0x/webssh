// Package hostops holds what WebSSH knows and does around saved hosts:
// server operations, discovery and the reachability check behind their
// permission, runtime inventory, host context, session insights and notes
// (one model: a note belongs to a saved host or to none, D-11).
//
// It serves the note without a host (notes.get, notes.save), the host
// context of a saved host (notes, favourite directories and command-set
// references under one revision, context*.go) and the minimal overview
// status. Packages built in parallel keep their own files: notes in
// notes*.go, the host context in context*.go, the overview in overview*.go.
package hostops

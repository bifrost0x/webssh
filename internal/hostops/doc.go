// Package hostops holds what WebSSH knows and does around saved hosts:
// server operations, discovery and the reachability check behind their
// permission, runtime inventory, host context, session insights and notes
// (one model: a note belongs to a saved host or to none, D-11).
//
// In M1 it serves the note without a host (notes.get, notes.save) and the
// minimal overview status. Two packages of the M1 plan work here in
// parallel: notes live in notes*.go, the overview in overview*.go.
package hostops

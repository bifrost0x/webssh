// Package jobs runs the background jobs of the process: periodic and
// scheduled jobs with one owner each, on-demand runs, cancellation and a
// bounded shutdown. Capabilities expose job functions; cmd/webssh
// registers them. The contract is described in
// docs/architecture/m2-contracts.md.
package jobs

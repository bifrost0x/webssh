// Package transfer moves files between the browser and a file source and
// between two sources: token-bound HTTP uploads and downloads, folder
// downloads as ZIP and host-to-host copies, with progress, conflict
// policy and cancellation. A transfer belongs to the user and the browser
// session, not to a realtime connection, so it survives a reconnect.
//
// The contract is described in docs/architecture/m2-contracts.md.
package transfer

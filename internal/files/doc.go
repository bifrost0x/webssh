// Package files is the protocol-neutral file workspace: one backend
// contract for SFTP and SMB, one path model, one decoding rule for
// preview and editor (D-23), the source registry of a browser session and
// the editor.
//
// Backends implement Backend and live in internal/files/sftp and
// internal/files/smb; cmd/webssh registers them. The contract is described
// in docs/architecture/m2-contracts.md.
package files

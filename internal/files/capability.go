package files

import "strings"

// Capability is one operation a source offers. The names are those of the
// source descriptor the page receives (capabilities[] in
// app/file_sources.py).
type Capability uint16

const (
	CapList Capability = 1 << iota
	CapRead
	CapWrite
	CapCreateFile
	CapChmod
	CapMkdir
	CapRename
	CapDelete
	CapPreview
	CapEdit
	CapRecursive
	CapRemoteTransfer
)

var capabilityNames = []struct {
	c    Capability
	name string
}{
	{CapList, "list"}, {CapRead, "read"}, {CapWrite, "write"},
	{CapCreateFile, "create-file"}, {CapChmod, "chmod"}, {CapMkdir, "mkdir"},
	{CapRename, "rename"}, {CapDelete, "delete"}, {CapPreview, "preview"},
	{CapEdit, "edit"}, {CapRecursive, "recursive"}, {CapRemoteTransfer, "remote-transfer"},
}

// Has reports whether every capability of want is in c.
func (c Capability) Has(want Capability) bool { return c&want == want }

// Names returns the wire names of c in catalog order.
func (c Capability) Names() []string {
	var out []string
	for _, n := range capabilityNames {
		if c.Has(n.c) {
			out = append(out, n.name)
		}
	}
	return out
}

func (c Capability) String() string { return strings.Join(c.Names(), ",") }

// CapAll is every capability but chmod: what SFTP and SMB offer by
// default. SFTP adds CapChmod when the admin switch is on and the server
// offers lsetstat@openssh.com.
const CapAll = CapList | CapRead | CapWrite | CapCreateFile | CapMkdir | CapRename |
	CapDelete | CapPreview | CapEdit | CapRecursive | CapRemoteTransfer

// Capabilities describes a source.
type Capabilities struct {
	Ops Capability
	// Replace lists the strategies Write supports for existing files, in
	// order of preference; empty when no safe replace exists.
	Replace []Strategy
	// SymlinkTargets: Write with FollowSymlink saves the link target (SFTP).
	SymlinkTargets bool
	// CaseInsensitive names compare case-folded (SMB): renames and the
	// subtree check use it.
	CaseInsensitive bool
	// RootWritable: the source root itself may be changed. An SMB share
	// root may not (only its children).
	RootWritable bool
}

// Kind is the protocol of a backend.
type Kind string

const (
	KindSFTP Kind = "sftp"
	KindSMB  Kind = "smb"
)

// SourceKind is the kind part of a source id ("<kind>:<handle>").
type SourceKind string

const (
	SourceSFTPSession SourceKind = "sftp-session" // the SFTP subsystem of a terminal session
	SourceSFTPQuick   SourceKind = "sftp-quick"   // Quick SFTP, also from a saved host
	SourceSMBQuick    SourceKind = "smb-quick"    // an SMB share
)

// Security is what the page shows about the transport of a source.
type Security struct {
	Encrypted, HostKeyVerified, SecureNegotiate, Signed bool
}

// Descriptor is the public description of an open source.
type Descriptor struct {
	SourceID  string
	Kind      Kind
	Label     string // "<share> on <host>", the session name, …
	Endpoint  string
	Protocol  string // "SFTP", "SMB 3.1.1"
	Ephemeral bool
	Security  Security
	// Access is the probe of the source root when it was opened (SMB,
	// AccessProber); nil when the backend cannot tell.
	Access *Access
}

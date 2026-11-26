package main

// smbArea wires the area "smb" (FS3): the SMB file backend (internal/files/smb).
// FS3 fills in the hooks; no other package edits this file.
func smbArea() extension {
	return extension{name: "smb"}
}

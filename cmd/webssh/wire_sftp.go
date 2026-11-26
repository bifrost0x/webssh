package main

// sftpArea wires the area "sftp" (FS2): the SFTP file backend (internal/files/sftp).
// FS2 fills in the hooks; no other package edits this file.
func sftpArea() extension {
	return extension{name: "sftp"}
}

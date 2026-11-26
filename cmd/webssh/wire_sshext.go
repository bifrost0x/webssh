package main

// sshextArea wires the area "sshext" (NW1): jump hosts with passwords, SOCKS5 login, keyboard-interactive and IDNA (internal/ssh/client, internal/idna2003).
// NW1 fills in the hooks; no other package edits this file.
func sshextArea() extension {
	return extension{name: "sshext"}
}

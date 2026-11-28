package main

// sshextArea wires the area "sshext" (NW1): jump hosts with passwords, SOCKS5 login, keyboard-interactive and IDNA (internal/ssh/client, internal/idna2003).
func sshextArea() extension {
	return extension{name: "sshext"}
}

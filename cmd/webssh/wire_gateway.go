package main

// gatewayArea wires the area "gateway" (NW2): the SSH gateway and Tailscale SSH (internal/ssh/gateway, internal/ssh/tailscale).
// NW2 fills in the hooks; no other package edits this file.
func gatewayArea() extension {
	return extension{name: "gateway"}
}

package main

// accountsArea wires the area "accounts" (ID4): account administration (internal/accounts, internal/auth, internal/session).
// ID4 fills in the hooks; no other package edits this file.
func accountsArea() extension {
	return extension{name: "accounts"}
}

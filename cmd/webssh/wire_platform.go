package main

// platformArea wires the area "platform" (PF1): data directory permissions (internal/platform).
// PF1 fills in the hooks; no other package edits this file.
func platformArea() extension {
	return extension{name: "platform"}
}

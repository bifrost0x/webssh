package main

// discoveryArea wires the area "discovery" (HO2): discovery, platform facts and the overview (internal/hostops, internal/hosts).
// HO2 fills in the hooks; no other package edits this file.
func discoveryArea() extension {
	return extension{name: "discovery"}
}

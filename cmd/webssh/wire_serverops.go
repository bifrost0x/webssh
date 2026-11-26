package main

// serveropsArea wires the area "serverops" (HO1): server operations, insights and Herdr (internal/hostops, internal/ssh/remotecmd).
// HO1 fills in the hooks; no other package edits this file.
func serveropsArea() extension {
	return extension{name: "serverops"}
}

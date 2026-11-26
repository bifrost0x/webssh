package main

// hostcontextArea wires the area "hostcontext" (HO3): host context, global host trust and profile exchange (internal/hostops, internal/ssh/hostkey, internal/hosts).
// HO3 fills in the hooks; no other package edits this file.
func hostcontextArea() extension {
	return extension{name: "hostcontext"}
}

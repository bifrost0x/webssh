package main

// schedulesArea wires the area "schedules" (AU2): automation schedules and permission jobs (internal/automation).
// AU2 fills in the hooks; no other package edits this file.
func schedulesArea() extension {
	return extension{name: "schedules"}
}

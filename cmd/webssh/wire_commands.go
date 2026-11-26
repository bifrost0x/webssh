package main

// commandsArea wires the area "commands" (CM1): commands and command sets (internal/commands).
// CM1 fills in the hooks; no other package edits this file.
func commandsArea() extension {
	return extension{name: "commands"}
}

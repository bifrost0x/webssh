package main

// terminalArea wires the area "terminal" (TM1): the rest of the terminal (internal/terminal).
// TM1 fills in the hooks; no other package edits this file.
func terminalArea() extension {
	return extension{name: "terminal"}
}

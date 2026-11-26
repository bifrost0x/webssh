package main

// automationArea wires the area "automation" (AU1): automation runbooks and runs (internal/automation).
// AU1 fills in the hooks; no other package edits this file.
func automationArea() extension {
	return extension{name: "automation"}
}

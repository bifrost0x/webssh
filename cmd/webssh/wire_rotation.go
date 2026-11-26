package main

// rotationArea wires the area "rotation" (OP2): secret rotation, maintenance and store repair (internal/backup, internal/admincli).
// OP2 fills in the hooks; no other package edits this file.
func rotationArea() extension {
	return extension{name: "rotation"}
}

package main

// operationsArea wires the area "operations" (OP3): audit, instance operations and the support report (internal/audit, internal/operations, internal/settings).
// OP3 fills in the hooks; no other package edits this file.
func operationsArea() extension {
	return extension{name: "operations"}
}

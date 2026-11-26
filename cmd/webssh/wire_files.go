package main

// filesArea wires the area "files" (FS1): the file workspace and the editor (internal/files).
// FS1 fills in the hooks; no other package edits this file.
func filesArea() extension {
	return extension{name: "files"}
}

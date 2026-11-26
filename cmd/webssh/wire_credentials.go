package main

// credentialsArea wires the area "credentials" (VA1): saved credentials and the legacy automation vault (internal/vault).
// VA1 fills in the hooks; no other package edits this file.
func credentialsArea() extension {
	return extension{name: "credentials"}
}

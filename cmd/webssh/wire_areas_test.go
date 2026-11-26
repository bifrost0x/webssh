package main

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// Every wire_<area>.go file is one entry of areaExtensions with the same
// name, and every entry has its file.
func TestAreaFilesMatchTheList(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, e := range entries {
		name, ok := strings.CutPrefix(e.Name(), "wire_")
		if !ok || strings.HasSuffix(name, "_test.go") || name == "areas.go" || !strings.HasSuffix(name, ".go") {
			continue
		}
		files = append(files, strings.TrimSuffix(name, ".go"))
	}
	var listed []string
	for _, area := range areaExtensions {
		listed = append(listed, area().name)
	}
	slices.Sort(files)
	sorted := slices.Sorted(slices.Values(listed))
	if !slices.Equal(files, sorted) || len(slices.Compact(slices.Clone(sorted))) != len(sorted) {
		t.Fatalf("wire files %v, listed areas %v", files, listed)
	}
	for _, name := range listed {
		if !slices.ContainsFunc(extensions, func(e extension) bool { return e.name == name }) {
			t.Errorf("area %s is not registered", name)
		}
	}
}

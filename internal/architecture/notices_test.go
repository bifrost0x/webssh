package architecture

import (
	"strings"
	"testing"
)

const noticesFile = "THIRD-PARTY-NOTICES"

// missingNotices returns the linked modules that THIRD-PARTY-NOTICES does
// not name on a line of its own as "Module: <path>" or in the module list of
// the Go project section.
func missingNotices(notices string, linked []string) []string {
	named := map[string]bool{}
	for line := range strings.SplitSeq(notices, "\n") {
		line = strings.TrimSpace(line)
		rest, ok := strings.CutPrefix(line, "Module: ")
		if !ok {
			rest, ok = strings.CutPrefix(line, "Modules: ")
		}
		for ok && rest != "" {
			field, tail, _ := strings.Cut(rest, ",")
			named[strings.Fields(strings.TrimSpace(field) + " x")[0]] = true
			rest = tail
		}
	}
	// The Go project section spans several lines; every golang.org/x
	// module on them counts.
	for f := range strings.FieldsSeq(notices) {
		f = strings.Trim(f, ",")
		if strings.HasPrefix(f, "golang.org/x/") {
			named[f] = true
		}
	}
	var missing []string
	for _, mod := range linked {
		if !named[mod] {
			missing = append(missing, mod)
		}
	}
	return missing
}

// Every module linked into the release binary is distributed with its
// license text.
func TestThirdPartyNoticesCoverModules(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	notices := string(readRepoFile(t, root, noticesFile))
	var linked []string
	for _, mod := range linkedModules(loadPackages(t, root), loadGraph(t)) {
		if mod != modulePath {
			linked = append(linked, mod)
		}
	}
	if len(linked) == 0 {
		t.Fatal("no linked modules found")
	}
	if missing := missingNotices(notices, linked); len(missing) > 0 {
		t.Errorf("%s has no license section for %v", noticesFile, missing)
	}
}

func TestMissingNotices(t *testing.T) {
	t.Parallel()
	notices := "Modules: Go standard library, golang.org/x/crypto,\ngolang.org/x/sys\n\nModule: github.com/a/b\nLicense: MIT\n"
	got := missingNotices(notices, []string{"github.com/a/b", "golang.org/x/crypto", "golang.org/x/sys", "github.com/c/d", "golang.org/x/term"})
	if strings.Join(got, " ") != "github.com/c/d golang.org/x/term" {
		t.Errorf("missing = %v", got)
	}
}

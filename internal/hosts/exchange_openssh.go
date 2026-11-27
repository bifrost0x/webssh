package hosts

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"fmt"
	"strings"
)

// knownHostsMessage is shown when an OpenSSH import is a known_hosts file.
const knownHostsMessage = "This is known_hosts host-key data, not an OpenSSH config. " +
	"Choose your SSH config file (usually ~/.ssh/config), or add hosts manually. " +
	"Host keys are not imported or trusted by this tool."

var errTooManyHosts = exchangeError("Import supports at most 100 hosts.")

// Preview is the result of reading an exchange document: one row per host
// and the warnings about the document as a whole.
type Preview struct {
	Records  []jsontext.Value
	Warnings []string
	rows     []record
}

// openSSHFields maps the four keywords the import understands.
var openSSHFields = map[string]string{"hostname": "host", "user": "username", "port": "port", "proxyjump": "jump_alias"}

// previewOpenSSH is _openssh. It never evaluates the configuration: only
// Host blocks with literal aliases and the keywords HostName, User, Port,
// ProxyJump and IdentityFile are read. Everything else (patterns, Match,
// global settings, other keywords) blocks the whole document, because it
// can change routing, authentication or run local commands.
func previewOpenSSH(source string, selector selectorCheck) (Preview, error) {
	lines := pySplitLines(source)
	for _, line := range lines {
		if !strings.HasPrefix(strings.TrimLeftFunc(line, pyIsSpace), "#") && knownHostLine.MatchString(line) {
			return Preview{}, exchangeError(knownHostsMessage)
		}
	}
	var (
		rows     []record
		warnings []string
		aliases  []string
		values   record
		unsafe   bool
	)
	flush := func() error {
		for _, alias := range aliases {
			in := record{}
			in.set("name", jsonString(alias))
			for _, m := range values.members {
				in.set(m.name, m.value)
			}
			row, err := exchangeRecord(in, selector)
			if err != nil {
				return err
			}
			if jump := row.text("jump_alias"); jump != "" && !exchangeAlias.MatchString(jump) {
				blockRow(&row, "This jump-host expression is unsupported.")
			}
			rows = append(rows, row)
			if len(rows) > exchangeMaxRecords {
				return errTooManyHosts
			}
		}
		return nil
	}
	for index, line := range lines {
		number := index + 1
		parts, err := shlexSplit(line)
		if err != nil {
			return Preview{}, exchangeError(fmt.Sprintf("Invalid quoting on line %d.", number))
		}
		if len(parts) == 0 {
			continue
		}
		// OpenSSH permits both "Keyword value" and "Keyword=value".
		keyword, rest := parts[0], parts[1:]
		if k, v, found := strings.Cut(keyword, "="); found {
			keyword, rest = k, append([]string{v}, rest...)
		} else if len(rest) > 0 && rest[0] == "=" {
			rest = rest[1:]
		}
		keyword = asciiLower(keyword)
		if keyword == "host" {
			if err := flush(); err != nil {
				return Preview{}, err
			}
			values, aliases = record{}, nil
			for _, alias := range rest {
				if exchangeAlias.MatchString(alias) {
					aliases = append(aliases, alias)
				}
			}
			if len(rest) == 0 || len(aliases) != len(rest) {
				unsafe = true
				warnings = append(warnings, fmt.Sprintf("Line %d: patterns require manual configuration.", number))
			}
			continue
		}
		if len(aliases) == 0 {
			unsafe = true
			warnings = append(warnings, fmt.Sprintf("Line %d: global or conditional settings require manual configuration.", number))
			continue
		}
		field, supported := openSSHFields[keyword]
		switch {
		case keyword == "identityfile":
			values.set("requires_key", jsonTrue)
		case supported && len(rest) == 1:
			if values.has(field) {
				break // the first value wins, as in OpenSSH
			}
			value := jsonString(rest[0])
			switch {
			case field == "port":
				port, ok := pyIntText(rest[0])
				if !ok {
					port = jsonInt(0)
				}
				value = port
			case field == "jump_alias" && asciiLower(rest[0]) == "none":
				value = jsonString("")
			}
			values.set(field, value)
		default:
			unsafe = true
			warnings = append(warnings, fmt.Sprintf("Line %d: unsupported directive requires manual configuration.", number))
		}
	}
	if err := flush(); err != nil {
		return Preview{}, err
	}
	seen := map[string]bool{}
	for _, row := range rows {
		key := aliasKey(row.text("name"))
		if seen[key] {
			unsafe = true
			warnings = append(warnings, "Overlapping Host blocks require manual configuration.")
			break
		}
		seen[key] = true
	}
	if unsafe {
		for i := range rows {
			blockRow(&rows[i], "Resolve unsupported configuration before importing this document.")
		}
	}
	return newPreview(rows, warnings), nil
}

// blockRow marks a preview row blocked and appends warning.
func blockRow(row *record, warning string) {
	row.set("blocked", jsonTrue)
	var list []string
	if v, ok := row.get("warnings"); ok {
		_ = json.Unmarshal(v, &list)
	}
	row.set("warnings", stringArray(append(list, warning)))
}

func newPreview(rows []record, warnings []string) Preview {
	p := Preview{Records: make([]jsontext.Value, len(rows)), Warnings: warnings, rows: rows}
	for i, r := range rows {
		p.Records[i] = r.encode()
	}
	if p.Warnings == nil {
		p.Warnings = []string{}
	}
	return p
}

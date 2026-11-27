package hosts

import (
	"encoding/json/jsontext"
	"slices"

	"github.com/bifrost0x/webssh/internal/pyjson"
)

// exchangeSource is the "source" and "format" of a preview or import
// request, decoded like json.loads did. LoneSurrogate is set when the
// source held an escaped unpaired surrogate, which Python could not encode
// as UTF-8.
type exchangeSource struct {
	Source        jsontext.Value
	Format        jsontext.Value
	LoneSurrogate bool
}

// previewImport is preview_import: it checks the source and reads it as
// an OpenSSH configuration or a WebSSH host document. It never stores
// anything.
func previewImport(in exchangeSource, selector selectorCheck) (Preview, error) {
	source, ok := asString(in.Source)
	if !ok {
		return Preview{}, exchangeError("Import must contain text.")
	}
	if in.LoneSurrogate {
		return Preview{}, exchangeError("Import must contain valid UTF-8.")
	}
	if len(source) > exchangeMaxInputBytes {
		return Preview{}, exchangeError("Import exceeds 64 KiB.")
	}
	format, _ := asString(in.Format)
	switch {
	case in.Format.Kind() == '"' && format == "openssh":
		return previewOpenSSH(source, selector)
	case in.Format.Kind() != '"' || format != "json":
		return Preview{}, exchangeError("Unsupported import format.")
	}
	return previewDocument(source, selector)
}

func previewDocument(source string, selector selectorCheck) (Preview, error) {
	doc, _, err := pyjson.Load([]byte(source))
	if err != nil {
		return Preview{}, exchangeError("Invalid JSON document.")
	}
	unsupported := exchangeError("Unsupported host exchange document.")
	members, ok := pyjson.Members(doc)
	if !ok || len(members) != 3 {
		return Preview{}, unsupported
	}
	format, _ := pyjson.Get(doc, "format")
	version, _ := pyjson.Get(doc, "version")
	hostsValue, hasHosts := pyjson.Get(doc, "hosts")
	if f, ok := asString(format); !ok || f != "webssh-hosts" || string(version) != "1" || !hasHosts {
		return Preview{}, unsupported
	}
	items, ok := pyjson.Items(hostsValue)
	if !ok || len(items) > exchangeMaxRecords {
		return Preview{}, unsupported
	}
	rows := make([]record, 0, len(items))
	for _, item := range items {
		fields, ok := pyjson.Members(item)
		if !ok {
			return Preview{}, errUnsupportedFields
		}
		var values record
		for _, m := range fields {
			if !slices.Contains(exchangeFields, m.Name) {
				return Preview{}, errUnsupportedFields
			}
			values.set(m.Name, m.Value)
		}
		row, err := exchangeRecord(values, selector)
		if err != nil {
			return Preview{}, err
		}
		rows = append(rows, row)
	}
	return newPreview(rows, nil), nil
}

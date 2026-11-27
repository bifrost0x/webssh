package hosts

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json/jsontext"
	"fmt"
	"slices"
	"time"

	"github.com/bifrost0x/webssh/internal/pyjson"
	"github.com/bifrost0x/webssh/internal/store"
)

// exportFields are copied from a saved host when present.
var exportFields = []string{"name", "host", "port", "username", "group", "favorite", "use_tmux", "auth_type", "platform_icon"}

// exportProfiles is export_profiles: the metadata of every saved host
// without secrets, key or route references. A jump host is named by its
// name; a SOCKS5 route is left out and flagged.
func exportProfiles(profiles, jumpHosts []record) []record {
	jumps := map[string]jsontext.Value{}
	for _, j := range jumpHosts {
		if id, ok := j.str("id"); ok {
			name, has := j.get("name")
			if !has {
				name = jsonNull // Python raises KeyError; a stored jump host always has a name
			}
			jumps[id] = name
		}
	}
	out := make([]record, 0, len(profiles))
	for _, p := range profiles {
		var row record
		for _, m := range p.members {
			if slices.Contains(exportFields, m.name) {
				row.set(m.name, m.value)
			}
		}
		// Keep the order of exportFields, as the Python dict comprehension does.
		row = ordered(row, exportFields)
		// Releases without Herdr reject unknown fields, so only enabled
		// options are written; a role only when one was chosen.
		for _, field := range []string{"herdr", "use_herdr"} {
			if v, _ := p.get(field); isTrue(v) {
				row.set(field, jsonTrue)
			}
		}
		if v, ok := p.get("role_override"); ok && inCatalog(roles, v) {
			row.set("role_override", v)
		}
		auth, _ := p.str("auth_type")
		row.set("requires_key", jsonBool(auth == "key"))
		if v, _ := p.get("jump_host_id"); truthy(v) {
			name := jsonString("Unresolved jump host")
			if id, ok := asString(v); ok {
				if n, found := jumps[id]; found {
					name = n
				}
			}
			row.set("jump_alias", name)
		}
		if v, _ := p.get("socks_proxy_id"); truthy(v) {
			row.set("socks_route_omitted", jsonTrue)
			row.set("warnings", stringArray([]string{socksRouteWarning}))
		}
		out = append(out, row)
	}
	return out
}

func ordered(r record, order []string) record {
	var out record
	for _, name := range order {
		if v, ok := r.get(name); ok {
			out.set(name, v)
		}
	}
	return out
}

// exchangeDocument is {"format": "webssh-hosts", "version": 1, "hosts": …}.
func exchangeDocument(rows []record) record {
	items := make([]jsontext.Value, len(rows))
	for i, r := range rows {
		items[i] = r.encode()
	}
	var doc record
	doc.set("format", jsonString("webssh-hosts"))
	doc.set("version", jsonInt(1))
	doc.set("hosts", pyjson.Array(items))
	return doc
}

// exportBatches is export_batches: documents of at most 100 hosts and
// 64 KiB as json.dumps writes them, each importable on its own. A single
// host larger than the limit still gets its own document.
func exportBatches(profiles, jumpHosts []record) [][]record {
	rows := exportProfiles(profiles, jumpHosts)
	var batches [][]record
	var batch []record
	for _, row := range rows {
		candidate := append(slices.Clone(batch), row)
		if len(candidate) > exchangeMaxRecords || len(pyDumps(exchangeDocument(candidate).encode())) > exchangeMaxInputBytes {
			batches = append(batches, batch)
			batch = []record{row}
		} else {
			batch = candidate
		}
	}
	if len(batch) > 0 || len(batches) == 0 {
		batches = append(batches, batch)
	}
	return batches
}

// pyDumps writes v as Python's json.dumps does with its defaults:
// ensure_ascii, ", " and ": " as separators, members in order. Numbers
// keep their stored text.
func pyDumps(v jsontext.Value) []byte {
	var b bytes.Buffer
	writePy(&b, v)
	return b.Bytes()
}

func writePy(b *bytes.Buffer, v jsontext.Value) {
	switch v.Kind() {
	case '{':
		members, _ := pyjson.Members(v)
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(pyjson.Quote(m.Name))
			b.WriteString(": ")
			writePy(b, m.Value)
		}
		b.WriteByte('}')
	case '[':
		items, _ := pyjson.Items(v)
		b.WriteByte('[')
		for i, item := range items {
			if i > 0 {
				b.WriteString(", ")
			}
			writePy(b, item)
		}
		b.WriteByte(']')
	case '"':
		s, _ := asString(v)
		b.WriteString(pyjson.Quote(s))
	default:
		b.Write(v)
	}
}

// flaskJSON writes v as Flask's jsonify did: keys sorted at every level,
// no spaces, ensure_ascii. The page turns the single document into the
// downloaded file with JSON.stringify, which keeps that member order.
func flaskJSON(v jsontext.Value) []byte {
	var b bytes.Buffer
	writeSorted(&b, v)
	return b.Bytes()
}

func writeSorted(b *bytes.Buffer, v jsontext.Value) {
	switch v.Kind() {
	case '{':
		members, _ := pyjson.Members(v)
		members = slices.Clone(members)
		slices.SortFunc(members, func(x, y pyjson.Member) int { return compareCodePoints(x.Name, y.Name) })
		b.WriteByte('{')
		for i, m := range members {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(pyjson.Quote(m.Name))
			b.WriteByte(':')
			writeSorted(b, m.Value)
		}
		b.WriteByte('}')
	case '[':
		items, _ := pyjson.Items(v)
		b.WriteByte('[')
		for i, item := range items {
			if i > 0 {
				b.WriteByte(',')
			}
			writeSorted(b, item)
		}
		b.WriteByte(']')
	case '"':
		s, _ := asString(v)
		b.WriteString(pyjson.Quote(s))
	default:
		b.Write(v)
	}
}

// compareCodePoints orders strings like Python: by code point. UTF-8
// byte order is code point order.
func compareCodePoints(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// exportArchive writes one stored (uncompressed) document per batch,
// webssh-hosts-1.json and up, as json.dumps writes them. Every batch is
// at most 64 KiB, except a single host that is larger on its own, and the
// export holds at most the saved hosts of one user, so the archive is
// built in memory.
func exportArchive(batches [][]record, now time.Time) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i, batch := range batches {
		f, err := zw.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("webssh-hosts-%d.json", i+1), Method: zip.Store, Modified: now})
		if err != nil {
			return nil, fmt.Errorf("hosts: export archive: %w", err)
		}
		if _, err := f.Write(pyDumps(exchangeDocument(batch).encode())); err != nil {
			return nil, fmt.Errorf("hosts: export archive: %w", err)
		}
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("hosts: export archive: %w", err)
	}
	return buf.Bytes(), nil
}

// exportRecords reads the saved hosts and jump hosts of owner in one
// snapshot.
func (s *Service) exportRecords(ctx context.Context, owner int64) (profiles, jumps []record, err error) {
	err = s.DB.Read(ctx, func(tx *store.Tx) error {
		if profiles, err = load(ctx, tx, profileTable, owner); err != nil {
			return err
		}
		jumps, err = load(ctx, tx, jumpTable, owner)
		return err
	})
	if err != nil {
		return nil, nil, classify(err, "Failed to load profiles")
	}
	return profiles, jumps, nil
}

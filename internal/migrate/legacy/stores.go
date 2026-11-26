package legacy

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// storeSpec describes one JSON store of the Python release.
type storeSpec struct {
	name       string // store name of app/storage_migrations.py, or the file stem
	file       string // path below the user directory, or below DATA_DIR for global stores
	versionKey string // "schema_version" (missing means 0) or "version" (required)
	versions   []int  // accepted versions
	listKey    string // key of the item list or map, if any
	topList    bool   // the document is a bare JSON array (commands.json)
	// maxBytes is the file size above which Python refuses to read the
	// store; 0 means Python has no limit and maxFileBytes applies.
	maxBytes int64
}

// Size limits Python checks before it reads a store (MAX_STORE_BYTES in
// app/automation_store.py and app/host_context.py; automation-runs.json is
// read with twice the limit in app/automation_service.py). A larger file is
// a store Python cannot read: STOP, as for any store Python rejects.
const (
	automationStoreBytes  = 1 << 20
	automationRunsBytes   = 2 * automationStoreBytes
	hostContextStoreBytes = 4 << 20
)

// userStores are the per-user JSON stores. Versions follow
// CURRENT_STORAGE_VERSIONS (app/storage_migrations.py): every version from
// 0 up to the current one is accepted, because Python migrates old
// documents on read and a never-read file keeps its old version. Stores
// with a "version" field accept only the versions their validators accept.
var userStores = []storeSpec{
	{name: "profiles", file: "profiles.json", versionKey: "schema_version", versions: upTo(3), listKey: "profiles"},
	{name: "jump_hosts", file: "jump_hosts.json", versionKey: "schema_version", versions: upTo(2), listKey: "jump_hosts"},
	{name: "socks_proxies", file: "socks_proxies.json", versionKey: "schema_version", versions: upTo(2), listKey: "socks_proxies"},
	{name: "smb_shares", file: "smb_shares.json", versionKey: "schema_version", versions: upTo(2), listKey: "smb_shares"},
	{name: "command_sets", file: "command_sets.json", versionKey: "schema_version", versions: upTo(2), listKey: "command_sets"},
	{name: "settings", file: "settings.json", versionKey: "schema_version", versions: upTo(2)},
	keysStore,
	{name: "commands", file: "commands.json", topList: true},
	{name: "host_context", file: "host_context.json", versionKey: "version", versions: []int{1}, listKey: "hosts", maxBytes: hostContextStoreBytes},
	{name: "automation", file: "automation.json", versionKey: "version", versions: []int{1}, listKey: "runbooks", maxBytes: automationStoreBytes},
	{name: "automation_runs", file: "automation-runs.json", versionKey: "version", versions: []int{1}, listKey: "runs", maxBytes: automationRunsBytes},
	{name: "credentials", file: "credentials.json", versionKey: "version", versions: []int{1}, listKey: "credentials", maxBytes: automationStoreBytes},
	{name: "automation_vault", file: "automation-vault.json", versionKey: "version", versions: []int{1, 2}, maxBytes: automationStoreBytes},
}

var keysStore = storeSpec{name: "keys", file: "keys/keys.json", versionKey: "schema_version", versions: upTo(2), listKey: "keys"}

var appSettingsStore = storeSpec{name: "app_settings", file: "app_settings.json", versionKey: "schema_version", versions: upTo(2)}

func upTo(n int) []int {
	v := make([]int, n+1)
	for i := range v {
		v[i] = i
	}
	return v
}

// Document is one decoded JSON store. Numbers decode as Number, the
// literal as written, so that integers above 2^53 survive as Python keeps
// them; the reader keeps the document as data and leaves its
// interpretation to the migration step of the entity.
type Document struct {
	Store   string
	Version int            // as stored; Object and Items are lifted to the current version
	Object  map[string]any // nil for a bare array
	Items   []any          // the list under listKey, or the bare array
	Entries map[string]any // the object under listKey when it is a map
	// Lifted reports that an older version was migrated in memory, as
	// Python does on read (app/storage_migrations.py).
	Lifted bool
	// LoneSurrogates reports strings with an escaped unpaired UTF-16
	// surrogate (for example "\ud800"), which Python writes with
	// ensure_ascii and reads back. Go strings cannot hold them; they are
	// replaced with U+FFFD and the store is flagged in the report.
	LoneSurrogates bool
}

// UserDocuments reads every JSON store of a user that exists. A store that
// is missing is absent from the result, as Python then uses its default.
func (s *Source) UserDocuments(userID int64) (map[string]Document, error) {
	out := map[string]Document{}
	for _, spec := range userStores {
		doc, err := s.readStore(userDir(userID)+"/"+spec.file, spec)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out[spec.name] = doc
	}
	return out, nil
}

// AppSettings reads DATA_DIR/app_settings.json.
func (s *Source) AppSettings() (Document, error) {
	return s.readStore(appSettingsStore.file, appSettingsStore)
}

// readStoreBytes reads the file of the user store named store with the
// size limit Python applies to it.
func (s *Source) readStoreBytes(name, store string) ([]byte, error) {
	for _, spec := range userStores {
		if spec.name == store {
			return s.readStoreFile(name, spec)
		}
	}
	return nil, fmt.Errorf("legacy: unknown store %q", store)
}

func (s *Source) readStoreFile(name string, spec storeSpec) ([]byte, error) {
	limit := int64(maxFileBytes)
	if spec.maxBytes > 0 {
		limit = spec.maxBytes
	}
	return readLimited(s.root, name, limit)
}

func (s *Source) readStore(name string, spec storeSpec) (Document, error) {
	data, err := s.readStoreFile(name, spec)
	if err != nil {
		return Document{}, err
	}
	doc, err := decodeStore(data, spec)
	if err != nil {
		return Document{}, fmt.Errorf("legacy: %s: %w", name, err)
	}
	return doc, nil
}

// decodeStore decodes and checks one store document. Invalid UTF-8,
// duplicate member names and unknown versions are rejected; Python would
// reject the first and the last as well (app/storage_utils.py,
// app/storage_migrations.py).
func decodeStore(data []byte, spec storeSpec) (Document, error) {
	if !utf8.Valid(data) {
		return Document{}, errors.New("invalid UTF-8")
	}
	doc := Document{Store: spec.name}
	var top any
	if err := json.Unmarshal(data, &top, numbersAsText); err != nil {
		// The bytes are valid UTF-8, so a decoding that only fails strictly
		// failed on an escaped lone surrogate.
		if json.Unmarshal(data, &top, numbersAsText, jsontext.AllowInvalidUTF8(true)) != nil {
			return Document{}, fmt.Errorf("invalid JSON: %w", err)
		}
		doc.LoneSurrogates = true
	}
	if spec.topList {
		return decodeCommands(doc, top, data)
	}
	object, ok := top.(map[string]any)
	if !ok {
		return Document{}, errors.New("not a JSON object")
	}
	doc.Object = object
	version, err := storeVersion(data, spec.versionKey)
	if err != nil {
		return Document{}, err
	}
	if !slices.Contains(spec.versions, version) {
		return Document{}, fmt.Errorf("unsupported %s %d", spec.versionKey, version)
	}
	doc.Version = version
	if spec.name == "profiles" && version < 3 {
		liftProfiles(object, version)
		doc.Lifted = true
	}
	if spec.listKey != "" {
		switch v := object[spec.listKey].(type) {
		case []any:
			doc.Items = v
		case map[string]any:
			doc.Entries = v
		case nil:
		default:
			return Document{}, fmt.Errorf("%s is neither a list nor an object", spec.listKey)
		}
	}
	return doc, nil
}

// commandWrapperVersions are the versions of the legacy object form of
// commands.json (app/command_manager.py _PR_COMMAND_WRAPPER_VERSIONS).
var commandWrapperVersions = []int{1, 2}

// decodeCommands accepts both forms Python reads: a bare list, or
// {"schema_version": 1|2, "commands": [...]}, which Python rewrites as a
// list on the next read.
func decodeCommands(doc Document, top any, data []byte) (Document, error) {
	switch v := top.(type) {
	case []any:
		doc.Items = v
		return doc, nil
	case map[string]any:
		version, err := storeVersion(data, "schema_version")
		_, present := v["schema_version"]
		list, isList := v["commands"].([]any)
		if err != nil || !present || !slices.Contains(commandWrapperVersions, version) || !isList {
			return Document{}, errors.New("unsupported commands document")
		}
		doc.Object, doc.Items, doc.Version, doc.Lifted = v, list, version, true
		return doc, nil
	}
	return Document{}, errors.New("commands document is neither a list nor an object")
}

// liftProfiles applies the profile migrations of app/storage_migrations.py
// in memory: 1 to 2 derives startup_mode, 2 to 3 drops the response-only
// tailscale_authorized flag.
func liftProfiles(object map[string]any, version int) {
	profiles, _ := object["profiles"].([]any)
	for _, p := range profiles {
		profile, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if _, has := profile["startup_mode"]; version <= 1 && !has {
			switch {
			case truthy(profile["command_set_id"]):
				profile["startup_mode"] = "command_set"
			case truthy(profile["command_id"]):
				profile["startup_mode"] = "command"
			case truthy(profile["startup_commands"]):
				profile["startup_mode"] = "free_text"
			default:
				profile["startup_mode"] = "none"
			}
		}
		delete(profile, "tailscale_authorized")
	}
	object["schema_version"] = Number("3")
}

// truthy is Python's truth value for decoded JSON.
func truthy(v any) bool {
	switch v := v.(type) {
	case nil:
		return false
	case bool:
		return v
	case Number:
		return !v.isZero()
	case string:
		return v != ""
	case []any:
		return len(v) > 0
	case map[string]any:
		return len(v) > 0
	}
	return true
}

// storeVersion reads a version member. Like Python's "type(v) is int"
// check it accepts only an integer literal: 1.0, true or "1" are rejected.
func storeVersion(data []byte, key string) (int, error) {
	var head map[string]jsontext.Value
	if err := json.Unmarshal(data, &head, jsontext.AllowInvalidUTF8(true)); err != nil {
		return 0, fmt.Errorf("invalid JSON object: %w", err)
	}
	raw, ok := head[key]
	if !ok {
		if key == "schema_version" {
			return 0, nil
		}
		return 0, fmt.Errorf("missing %s", key)
	}
	text := string(raw)
	if text == "" || len(text) > 6 || strings.Trim(text, "0123456789") != "" || (len(text) > 1 && text[0] == '0') {
		return 0, fmt.Errorf("invalid %s", key)
	}
	n, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("invalid %s", key)
	}
	return n, nil
}

// QuarantinedAccounts lists the directories of deleted accounts below
// deleted_users/ (app/user_lifecycle.py delete_user_account). Their numeric
// id may have been reused by a later account.
func (s *Source) QuarantinedAccounts() ([]string, error) {
	return s.listDirs("deleted_users")
}

// LogFiles lists the application and audit logs below logs/ (app.log,
// security_audit.log and their rotations). logs/ is a runtime path, so
// links there do not stop the migration; only regular files are listed.
func (s *Source) LogFiles() ([]string, error) {
	entries, err := fs.ReadDir(s.root.FS(), "logs")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("legacy: list logs: %w", err)
	}
	var files []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.Contains(e.Name(), ".log") {
			files = append(files, "logs/"+e.Name())
		}
	}
	return files, nil
}

// UserDirectories lists the per-user directories below users/.
func (s *Source) UserDirectories() ([]string, error) {
	return s.listDirs("users")
}

func (s *Source) listDirs(name string) ([]string, error) {
	entries, err := s.listDir(name)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") {
			dirs = append(dirs, e.Name())
		}
	}
	return dirs, nil
}

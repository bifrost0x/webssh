package protocol

// Payloads of keys.* (internal/vault). The requests carry the members the
// page sends today (profile-manager.js) plus the passphrase of a protected
// key and the step-up grant; the results are the success payloads of the
// Python release without "success". keys.list takes Empty.

// KeySummary is one SSH key as the page lists it. Filename and Encrypted
// are kept for the shape of the Python release ("<id>.pem", true).
type KeySummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Filename   string `json:"filename"`
	KeyType    string `json:"key_type"`
	Encrypted  bool   `json:"encrypted"`
	UploadedAt string `json:"uploaded_at"`
	Usable     bool   `json:"usable"`
}

// KeysList is the result of keys.list.
type KeysList struct {
	Keys []KeySummary `json:"keys"`
}

// KeyResult is the result of keys.upload, keys.rename and keys.replace.
type KeyResult struct {
	Key KeySummary `json:"key"`
}

// KeysUpload stores a new key (as today: upload_key).
type KeysUpload struct {
	Name       string `json:"name"`
	KeyContent string `json:"key_content"`
	Passphrase string `json:"passphrase,omitzero"`
	StepUp     string `json:"step_up,omitzero"`
}

// KeysRename renames a key (as today: rename_key).
type KeysRename struct {
	KeyID string `json:"key_id"`
	Name  string `json:"name"`
}

// KeysReplace replaces the material of a key (as today: replace_key).
type KeysReplace struct {
	KeyID      string `json:"key_id"`
	KeyContent string `json:"key_content"`
	Passphrase string `json:"passphrase,omitzero"`
	StepUp     string `json:"step_up,omitzero"`
}

// KeysDelete removes a key (as today: delete_key).
type KeysDelete struct {
	KeyID  string `json:"key_id"`
	StepUp string `json:"step_up,omitzero"`
}

// MaxKeyPayload bounds the payload of keys.upload and keys.replace: a key
// text of 64 KiB, JSON-escaped, plus name, passphrase and grant.
const MaxKeyPayload = 192 << 10

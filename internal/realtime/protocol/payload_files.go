package protocol

// Payloads of files.* (internal/files). The requests carry the members the
// file pages send today (file-directory-requests.js, file-preview.js,
// sftp-file-manager.js, file-mutation-dialog.js); the results carry the
// members of the Python push events. The shim adds the correlation
// members (operation, cursor) and turns the results into those events.

// Message types of the area "files" (FS1).
const (
	TypeFilesList        = "files.list"
	TypeFilesListCancel  = "files.list.cancel"
	TypeFilesHome        = "files.home"
	TypeFilesPreview     = "files.preview"
	TypeFilesImage       = "files.preview.image"
	TypeFilesEditOpen    = "files.edit.open"
	TypeFilesEditSave    = "files.edit.save"
	TypeFilesMkdir       = "files.mkdir"
	TypeFilesCreate      = "files.create"
	TypeFilesRename      = "files.rename"
	TypeFilesDelete      = "files.delete"
	TypeFilesSourceClose = "files.source.close"
)

// FileRef names a source and correlates the answer (every request).
type FileRef struct {
	SourceID  string `json:"source_id"`
	RequestID string `json:"request_id"`
}

// FileSource is the public descriptor of a source (file_source of today).
type FileSource struct {
	SourceID     string            `json:"source_id"`
	Kind         string            `json:"kind"`
	Label        string            `json:"label"`
	Endpoint     string            `json:"endpoint"`
	Protocol     string            `json:"protocol"`
	Capabilities []string          `json:"capabilities"`
	Ephemeral    bool              `json:"ephemeral"`
	Security     map[string]bool   `json:"security"`
	Access       map[string]string `json:"access"`
}

// FileEntry is one directory entry as the page lists it.
type FileEntry struct {
	Name      string  `json:"name"`
	Size      int64   `json:"size"`
	Mode      uint32  `json:"mode"`
	IsDir     bool    `json:"is_dir"`
	IsSymlink bool    `json:"is_symlink"`
	Modified  float64 `json:"modified"`
}

// FilesList reads one page of a directory (list_directory). Cursor is
// empty for the first page; the page's numeric 0 is left out by the shim.
type FilesList struct {
	FileRef
	RemotePath string `json:"remote_path"`
	Cursor     string `json:"cursor,omitzero"`
}

// FilesListing is the result of files.list (directory_listing).
type FilesListing struct {
	FileRef
	Path       string      `json:"path"`
	Files      []FileEntry `json:"files"`
	NextCursor *string     `json:"next_cursor"`
}

// FilesListCancel closes a listing by its cursor or by the request id of
// its first page (cancel_directory_listing).
type FilesListCancel struct {
	FileRef
	Cursor           string `json:"cursor,omitzero"`
	ListingRequestID string `json:"listing_request_id,omitzero"`
}

// FilesPath is the result of files.home (home_directory) and the answer
// of files.mkdir, files.delete and files.create.
type FilesPath struct {
	FileRef
	Path string `json:"path"`
}

// FilesPreview reads a text preview (preview_file). Zero values take the
// defaults of the Python release.
type FilesPreview struct {
	FileRef
	Path      string `json:"path"`
	Offset    *int64 `json:"offset,omitzero"`
	MaxBytes  *int64 `json:"max_bytes,omitzero"`
	TailLines *int64 `json:"tail_lines,omitzero"`
}

// FilesPreviewData is the result of files.preview (preview_data). Content
// is null for binary content.
type FilesPreviewData struct {
	FileRef
	Path      string  `json:"path"`
	Filename  string  `json:"filename"`
	Content   *string `json:"content"`
	Size      int64   `json:"size"`
	ReadSize  int64   `json:"read_size"`
	Truncated bool    `json:"truncated"`
	IsBinary  bool    `json:"is_binary"`
	Offset    int64   `json:"offset"`
	Encoding  string  `json:"encoding,omitzero"`
}

// FilesImage reads a whole file for the image preview
// (download_file_binary); ForPreview must be true, as in Python.
type FilesImage struct {
	FileRef
	RemotePath string `json:"remote_path"`
	ForPreview bool   `json:"for_preview"`
}

// FilesImageData is the result of files.preview.image
// (file_download_ready_binary).
type FilesImageData struct {
	FileRef
	Path       string `json:"path"`
	Filename   string `json:"filename"`
	FileData   string `json:"file_data"` // base64
	Size       int64  `json:"size"`
	ForPreview bool   `json:"for_preview"`
	Encoding   string `json:"encoding"` // "base64"
}

// FilesEditOpen loads a file for the editor (open_file_for_edit).
type FilesEditOpen struct {
	FileRef
	Path string `json:"path"`
}

// FilesEditData is the result of files.edit.open (edit_data).
type FilesEditData struct {
	FileRef
	Path          string `json:"path"`
	Filename      string `json:"filename"`
	Content       string `json:"content"`
	Size          int64  `json:"size"`
	Encoding      string `json:"encoding"`
	Newline       string `json:"newline"`
	Revision      string `json:"revision"`
	OriginalBytes string `json:"original_bytes"` // base64
	Endpoint      string `json:"endpoint"`
}

// FilesEditSave saves editor text (save_file).
type FilesEditSave struct {
	FileRef
	Path             string `json:"path"`
	Content          string `json:"content"`
	Encoding         string `json:"encoding,omitzero"`
	Newline          string `json:"newline,omitzero"`
	ExpectedRevision string `json:"expected_revision,omitzero"`
	ReplaceStrategy  string `json:"replace_strategy,omitzero"`
	SaveChallenge    string `json:"save_challenge,omitzero"`
}

// FilesSaved is the result of files.edit.save (file_saved).
type FilesSaved struct {
	FileRef
	Path           string   `json:"path"`
	Revision       string   `json:"revision,omitzero"`
	WarningCode    string   `json:"warning_code,omitzero"`
	RecoveryLeaves []string `json:"recovery_leaves,omitzero"`
}

// FilesMkdir creates a directory (create_directory).
type FilesMkdir struct {
	FileRef
	RemotePath string `json:"remote_path"`
}

// FilesCreate creates an empty file (create_file).
type FilesCreate struct {
	FileRef
	ParentPath string `json:"parent_path"`
	Name       string `json:"name"`
}

// FilesCreated is the result of files.create (file_created).
type FilesCreated struct {
	FileRef
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// FilesRename moves an item on its source (rename_file).
type FilesRename struct {
	FileRef
	OldPath string `json:"old_path"`
	NewPath string `json:"new_path"`
}

// FilesRenamed is the result of files.rename (file_renamed).
type FilesRenamed struct {
	FileRef
	OldPath string `json:"old_path"`
	NewPath string `json:"new_path"`
}

// FilesDelete removes an item, a directory with its content
// (delete_item).
type FilesDelete struct {
	FileRef
	Path string `json:"path"`
}

// FilesSourceClose closes a Quick SFTP or SMB source
// (file_source_disconnect); RequestID is optional here.
type FilesSourceClose struct {
	SourceID  string `json:"source_id"`
	RequestID string `json:"request_id,omitzero"`
}

// FilesSourceClosed is the result of files.source.close.
type FilesSourceClosed struct {
	SourceID string `json:"source_id"`
}

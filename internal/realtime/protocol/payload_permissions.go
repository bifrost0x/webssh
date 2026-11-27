package protocol

// Payloads of permissions.* (internal/automation): single permission
// changes and the permission jobs of the file workspace
// (sftp-file-manager.js, permission-job-dialog.js). The results are
// objects built by the jobs: the permission state, or the job state; the
// shim adds the correlation members and turns them into the push events
// file_permissions, file_permissions_changed and file_permissions_job.

// Message types of the area "permissions" (AU2).
const (
	TypePermissionsGet        = "permissions.get"
	TypePermissionsSet        = "permissions.set"
	TypePermissionsJobPrepare = "permissions.job.prepare"
	TypePermissionsJobGet     = "permissions.job.get"
	TypePermissionsJobApply   = "permissions.job.apply"
	TypePermissionsJobCancel  = "permissions.job.cancel"
)

// PermissionsGet inspects one object (get_file_permissions).
type PermissionsGet struct {
	FileRef
	Path string `json:"path"`
}

// PermissionsSet changes the mode of one inspected object
// (set_file_permissions); ExpectedMetadata is the metadata token of the
// inspection.
type PermissionsSet struct {
	FileRef
	Path             string `json:"path"`
	Mode             string `json:"mode"`
	ExpectedMetadata string `json:"expected_metadata,omitzero"`
}

// PermissionsJobPrepare starts the scan of a permission job
// (prepare_file_permissions).
type PermissionsJobPrepare struct {
	FileRef
	Paths         []string `json:"paths"`
	Recursive     bool     `json:"recursive,omitzero"`
	FileMode      string   `json:"file_mode"`
	DirectoryMode string   `json:"directory_mode"`
}

// PermissionsJob names an owned job (get, apply and cancel).
type PermissionsJob struct {
	FileRef
	JobID string `json:"job_id"`
}

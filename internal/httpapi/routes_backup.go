package httpapi

// Routes of the area "backup" (OP1): online backup, upload, restore and the recovery check after a restore.
// OP1 moves each route it builds from backupPreview to backupBuilt with its
// access level; no other package edits this file.

var backupBuilt = []route{}

var backupPreview = []string{
	"POST /admin/api/backups",
	"GET /admin/api/backups/{operation_id}",
	"POST /admin/api/backups/{operation_id}/cancel",
	"POST /admin/api/backups/{operation_id}/download",
	"POST /admin/api/backups/{operation_id}/restore",
	"POST /admin/api/backups/{operation_id}/restore/prepare",
	"GET /admin/api/backups/restore/status",
	"POST /admin/api/backups/upload",
	"POST /api/account/recovery-check",
}

package httpapi

// Routes of the area "backup" (OP1): online backup, upload, restore and the recovery check after a restore.
// No other package edits this file.

var backupBuilt = []route{
	{"POST /admin/api/backups", AccessAdmin},
	{"GET /admin/api/backups/{operation_id}", AccessAdmin},
	{"POST /admin/api/backups/{operation_id}/cancel", AccessAdmin},
	{"POST /admin/api/backups/{operation_id}/download", AccessAdmin},
	{"POST /admin/api/backups/{operation_id}/restore", AccessAdmin},
	{"POST /admin/api/backups/{operation_id}/restore/prepare", AccessAdmin},
	{"GET /admin/api/backups/restore/status", AccessAdmin},
	{"POST /admin/api/backups/upload", AccessAdmin},
	{"POST /api/account/recovery-check", AccessUser},
}

package config

import (
	"fmt"
	"math/big"
	"time"
)

const (
	kib = 1024
	mib = 1024 * kib
	gib = 1024 * mib
)

// loadLimits follows config.py from AUDIT_LOG_MAX_BYTES to the connection
// store limits.
func loadLimits(p *parser, c *Config) {
	c.Audit.LogMaxBytes = p.positive("AUDIT_LOG_MAX_BYTES", 10*mib)
	c.Audit.BackupCount = int(p.positive("AUDIT_LOG_BACKUP_COUNT", 5))
	b := &c.Backup
	b.MaxMembers = p.positive("BACKUP_MAX_MEMBERS", 10000)
	b.MaxFileSize = p.positive("BACKUP_MAX_FILE_SIZE", gib)
	b.MaxTotalSize = p.positive("BACKUP_MAX_TOTAL_SIZE", 10*gib)
	b.MaxCompressionRatio = p.positive("BACKUP_MAX_COMPRESSION_RATIO", 200)
	b.MaxManifestSize = p.positive("BACKUP_MAX_MANIFEST_SIZE", 10*mib)
	b.UploadMaxSize = p.positive("BACKUP_UPLOAD_MAX_SIZE", gib)
	b.OperationTimeout = time.Duration(min(p.positive("BACKUP_OPERATION_TIMEOUT", 1800), 1<<32)) * time.Second
	b.DownloadTTL = time.Duration(min(p.positive("BACKUP_DOWNLOAD_TTL", 600), 1<<32)) * time.Second
	if !p.failed() {
		c.BackupTempDir = pyPath(p.raw("BACKUP_TEMP_DIR", pyTempDir(p.get)+"/webssh-backup-operations"))
		p.record("BACKUP_TEMP_DIR", c.BackupTempDir)
	}
	b.RecoveryDurable = p.flag("BACKUP_RECOVERY_DURABLE", "BACKUP_RECOVERY_DURABLE", "false")

	loadQuotas(p, c)

	c.Files.SFTP.OperationTimeout = time.Duration(p.positive("SFTP_OPERATION_TIMEOUT", 30)) * time.Second
	c.Files.Transfers.MaxUpload = p.positive("MAX_UPLOAD_SIZE", 100*mib)
	editorMax := p.positiveBig("MAX_EDITOR_FILE_SIZE", big.NewInt(5*mib))
	editorRate := p.boundedBig("EDITOR_SAVE_BYTES_PER_MINUTE", mul(editorMax, 4), editorMax, mul(editorMax, 64))
	c.Files.MaxEditorBytes, c.Files.EditorBytesPerMinute = saturate(editorMax), saturate(editorRate)
	p.record("SOCKETIO_MAX_MESSAGE_SIZE", new(big.Int).Add(mul(editorMax, 6), big.NewInt(64*kib)).String())

	in := &c.Terminal.Input
	in.MaxBytes = int(p.bounded("SSH_INPUT_MAX_BYTES", 128*kib, 4*kib, 256*kib))
	in.SessionBurstBytes = int(p.bounded("SSH_INPUT_SESSION_BURST_BYTES", 256*kib, int64(in.MaxBytes), 2*mib))
	in.SessionBytesPerSecond = int(p.bounded("SSH_INPUT_SESSION_BYTES_PER_SECOND", 256*kib, 4*kib, 2*mib))
	in.UserBurstBytes = int(p.bounded("SSH_INPUT_USER_BURST_BYTES", 512*kib, int64(in.SessionBurstBytes), 4*mib))
	in.UserBytesPerSecond = int(p.bounded("SSH_INPUT_USER_BYTES_PER_SECOND", 512*kib, 4*kib, 4*mib))

	c.Stores.CommandMaxRecords = int(p.bounded("COMMAND_MAX_RECORDS", 500, 10, 2000))
	c.Stores.CommandSetMaxRecords = int(p.bounded("COMMAND_SET_MAX_RECORDS", 500, 10, 2000))
	c.Stores.CommandSetMaxSteps = int(p.bounded("COMMAND_SET_MAX_STEPS", 64, 1, 256))
	c.Stores.CommandOSMaxEntries = int(p.bounded("COMMAND_OS_MAX_ENTRIES", 16, 1, 64))
	commandStore := p.bounded("COMMAND_STORE_MAX_BYTES", 2*mib, 64*kib, 8*mib)
	c.Stores.CommandStoreMaxBytes = int(commandStore)
	c.Stores.CommandConfigMaxBytes = int(p.bounded("COMMAND_CONFIG_MAX_BYTES", 4*mib, commandStore, 16*mib))

	p.bounded("FILE_CONTROL_MAX_PATH_BYTES", 4096, 512, 16*kib)
	p.adminSwitch("SFTP_CHMOD_ENABLED", false)
	c.Files.SFTP.MaxNameBytes = int(p.bounded("REMOTE_FILENAME_MAX_BYTES", 4096, 255, 16*kib))
	c.Files.SFTP.MaxMetadataBytes = int(p.bounded("REMOTE_LISTING_MAX_METADATA_BYTES", 4*mib, 64*kib, 16*mib))
	c.Files.ListingPageSize = int(p.bounded("REMOTE_LISTING_PAGE_SIZE", 500, 50, 1000))
	c.Files.SnapshotTTL = time.Duration(p.bounded("REMOTE_LISTING_SNAPSHOT_TTL_SECONDS", 60, 10, 300)) * time.Second
	c.Files.SnapshotsTotal = int(p.bounded("REMOTE_LISTING_SNAPSHOT_MAX_STATES", 8, 1, 64))
	c.Files.SnapshotsPerUser = int(p.bounded("REMOTE_LISTING_SNAPSHOT_MAX_PER_USER", 4, 1, 8))
	c.Files.SFTP.MaxPacketBytes = int(p.bounded("SFTP_MAX_PACKET_BYTES", mib, 64*kib, 4*mib))
	c.Files.SFTP.MaxHandleBytes = int(p.bounded("SFTP_MAX_HANDLE_BYTES", 16*kib, 256, 64*kib))
	c.Files.ControlBytesPerMin = p.bounded("FILE_CONTROL_BYTES_PER_MINUTE", 2*mib, 64*kib, 16*mib)

	s := &c.Stores
	s.ProfileMaxRecords = int(p.bounded("PROFILE_MAX_RECORDS", 500, 10, 2000))
	s.JumpHostMaxRecords = int(p.bounded("JUMP_HOST_MAX_RECORDS", 100, 10, 1000))
	s.SOCKSProxyMaxRecords = int(p.bounded("SOCKS_PROXY_MAX_RECORDS", 100, 10, 1000))
	s.ConnectionStoreMaxBytes = int(p.bounded("CONNECTION_STORE_MAX_BYTES", 2*mib, 64*kib, 8*mib))
	store := int64(s.ConnectionStoreMaxBytes)
	s.ConnectionConfigMaxBytes = int(p.bounded("CONNECTION_CONFIG_MAX_BYTES", 4*mib, store, 16*mib))
	s.ConnectionStoreRecoveryMaxBytes = int(p.bounded("CONNECTION_STORE_RECOVERY_MAX_BYTES", max(16*mib, store), store, 64*mib))
	records := int64(max(s.ProfileMaxRecords, s.JumpHostMaxRecords, s.SOCKSProxyMaxRecords))
	s.ConnectionStoreRecoveryMaxRecords = int(p.bounded("CONNECTION_STORE_RECOVERY_MAX_RECORDS", max(10_000, records), records, 100_000))
}

// loadQuotas follows config.py through the quotas and the background
// worker pool.
func loadQuotas(p *parser, c *Config) {
	q := func(name string, def int64) *big.Int { return p.positiveBig(name, big.NewInt(def)) }
	sshGlobal := q("QUOTA_SSH_SESSION_GLOBAL", 10)
	sshUser := q("QUOTA_SSH_SESSION_PER_USER", 5)
	quickGlobal := q("QUOTA_QUICK_CONNECTION_GLOBAL", 12)
	quickUser := q("QUOTA_QUICK_CONNECTION_PER_USER", 3)
	transferGlobal := q("QUOTA_TRANSFER_GLOBAL", 8)
	transferUser := q("QUOTA_TRANSFER_PER_USER", 2)
	tempGlobal := q("QUOTA_TEMP_BYTES_GLOBAL", gib)
	tempUser := q("QUOTA_TEMP_BYTES_PER_USER", 512*mib)
	jobGlobal := q("QUOTA_BACKGROUND_JOB_GLOBAL", 4)
	jobUser := q("QUOTA_BACKGROUND_JOB_PER_USER", 1)
	quotaPair(p, "SSH_SESSION", sshGlobal, sshUser, true)
	quotaPair(p, "QUICK_CONNECTION", quickGlobal, quickUser, true)
	quotaPair(p, "TRANSFER", transferGlobal, transferUser, true)
	quotaPair(p, "TEMP_BYTES", tempGlobal, tempUser, false)
	quotaPair(p, "BACKGROUND_JOB", jobGlobal, jobUser, false)
	if p.failed() {
		return
	}
	c.Terminal.SessionsGlobal, c.Terminal.SessionsPerUser = int(saturate(sshGlobal)), int(saturate(sshUser))
	c.Quotas = map[string]QuotaLimit{
		"ssh_session":      quotaLimit(sshGlobal, sshUser),
		"quick_connection": quotaLimit(quickGlobal, quickUser),
		"transfer":         quotaLimit(transferGlobal, transferUser),
		"temp_bytes":       quotaLimit(tempGlobal, tempUser),
		"background_job":   quotaLimit(jobGlobal, jobUser),
	}
	p.record("MAX_SESSIONS", sshGlobal.String())

	cleanup := int64(8)
	if pyIsTrue(p.raw("LDAP_ENABLED", "false")) {
		cleanup++
	}
	if pyIsTrue(p.raw("SMB_ENABLED", "false")) {
		cleanup++
	}
	const workersMax = 128
	minimum := new(big.Int).Add(big.NewInt(cleanup), sshGlobal)
	minimum.Add(minimum, jobGlobal)
	p.record("BACKGROUND_CLEANUP_JOBS", fmt.Sprint(cleanup))
	p.record("BACKGROUND_WORKERS_MIN", minimum.String())
	if minimum.Cmp(big.NewInt(workersMax)) > 0 {
		p.fail(configError("QUOTA_SSH_SESSION_GLOBAL", "CONFIGURATION ERROR: QUOTA_SSH_SESSION_GLOBAL plus QUOTA_BACKGROUND_JOB_GLOBAL exceeds the supported background worker capacity"))
		return
	}
	workersMin := minimum.Int64()
	workers := p.positive("BACKGROUND_WORKERS", workersMin)
	if p.failed() {
		return
	}
	if workers < workersMin {
		p.warn(WarnPython, "BACKGROUND_WORKERS", "BACKGROUND_WORKERS=%d is below the required minimum of %d; using %d.", workers, workersMin, workersMin)
		workers = workersMin
	}
	if workers > workersMax {
		p.fail(configError("BACKGROUND_WORKERS", fmt.Sprintf("CONFIGURATION ERROR: BACKGROUND_WORKERS must be between %d and %d", workersMin, workersMax)))
		return
	}
	p.record("BACKGROUND_WORKERS", fmt.Sprint(workers))
	grace := p.positive("RUNTIME_SHUTDOWN_GRACE_SECONDS", 5)
	if !p.failed() && grace > 30 {
		p.fail(configError("RUNTIME_SHUTDOWN_GRACE_SECONDS", "CONFIGURATION ERROR: RUNTIME_SHUTDOWN_GRACE_SECONDS must be between 1 and 30"))
		return
	}
	c.ShutdownGrace = seconds(grace)
}

func mul(v *big.Int, n int64) *big.Int { return new(big.Int).Mul(v, big.NewInt(n)) }

// quotaLimit saturates a validated pair; a per-user limit below the
// global one stays below it when both exceed int64.
func quotaLimit(global, perUser *big.Int) QuotaLimit {
	l := QuotaLimit{Global: saturate(global), PerUser: saturate(perUser)}
	if l.PerUser == l.Global && perUser.Cmp(global) < 0 {
		l.PerUser--
	}
	return l
}

func quotaPair(p *parser, kind string, global, perUser *big.Int, fair bool) {
	if p.failed() {
		return
	}
	if cmp := perUser.Cmp(global); cmp > 0 || fair && cmp == 0 {
		relation := "at most"
		if fair {
			relation = "below"
		}
		p.fail(configError("QUOTA_"+kind+"_PER_USER", fmt.Sprintf("CONFIGURATION ERROR: QUOTA_%s_PER_USER must be %s QUOTA_%s_GLOBAL", kind, relation, kind)))
	}
}

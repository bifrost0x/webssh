package protocol

import "slices"

// Direction says who sends a message type.
type Direction string

// Directions of the catalog.
const (
	// ClientRequest: the browser sends it, with an ID when it wants a
	// result. The owner registers a Route for it.
	ClientRequest Direction = "client"
	// ServerEvent: the server pushes it without an ID.
	ServerEvent Direction = "server"
)

// Message types of schema v1 (M1). Payload shapes are the types in
// payload_*.go; "as today" means the payload of the Socket.IO event the
// compatibility shim maps to, unchanged (docs/architecture/m1-contracts.md).
const (
	TypeHello = "hello"

	TypeTerminalOpen         = "terminal.open"
	TypeTerminalCancel       = "terminal.cancel"
	TypeTerminalDiscardLate  = "terminal.discard_late"
	TypeTerminalAttach       = "terminal.attach"
	TypeTerminalDetach       = "terminal.detach"
	TypeTerminalClose        = "terminal.close"
	TypeTerminalResize       = "terminal.resize"
	TypeTerminalRename       = "terminal.rename"
	TypeSessionKeepalive     = "session.keepalive"
	TypeTerminalClosed       = "terminal.closed"
	TypeTerminalTimeoutWarn  = "terminal.timeout_warning"
	TypeTerminalResync       = "terminal.resync_required"
	TypeTerminalInputReject  = "terminal.input_rejected"
	TypeTerminalInputAck     = "terminal.input_ack"
	TypePromptHostKey        = "prompt.host_key"
	TypePromptBanner         = "prompt.banner"
	TypePromptClosed         = "prompt.closed"
	TypePromptAnswer         = "prompt.answer"
	TypeHostsProfileList     = "hosts.profile.list"
	TypeHostsProfileSave     = "hosts.profile.save"
	TypeHostsProfileDelete   = "hosts.profile.delete"
	TypeHostsProfileOrganize = "hosts.profile.organize"
	TypeHostsProfileMove     = "hosts.profile.move"
	TypeHostsJumpList        = "hosts.jump.list"
	TypeHostsJumpSave        = "hosts.jump.save"
	TypeHostsJumpDelete      = "hosts.jump.delete"
	TypeHostsSOCKSList       = "hosts.socks.list"
	TypeHostsSOCKSSave       = "hosts.socks.save"
	TypeHostsSOCKSDelete     = "hosts.socks.delete"
	TypeKeysList             = "keys.list"
	TypeKeysUpload           = "keys.upload"
	TypeKeysRename           = "keys.rename"
	TypeKeysReplace          = "keys.replace"
	TypeKeysDelete           = "keys.delete"
	TypeSettingsTheme        = "settings.theme.set"
	TypeSettingsConfirmClose = "settings.confirm_close.set"
	TypeSettingsDisconnect   = "settings.disconnect_action.set"
	TypeNotesGet             = "notes.get"
	TypeNotesSave            = "notes.save"
)

// MessageType describes one entry of the catalog.
type MessageType struct {
	Name string
	Dir  Direction
	// Owner is the package that registers (requests) or sends (events) it.
	Owner string
}

// v1 is the catalog of schema v1. TypeResult is not listed: it is the
// reply to every request and owned by the dispatcher.
var v1 = []MessageType{
	{TypeHello, ServerEvent, "internal/realtime"},
	{TypeSessionKeepalive, ClientRequest, "internal/realtime"},

	{TypeTerminalOpen, ClientRequest, "internal/terminal"},
	{TypeTerminalCancel, ClientRequest, "internal/terminal"},
	{TypeTerminalDiscardLate, ClientRequest, "internal/terminal"},
	{TypeTerminalAttach, ClientRequest, "internal/terminal"},
	{TypeTerminalDetach, ClientRequest, "internal/terminal"},
	{TypeTerminalClose, ClientRequest, "internal/terminal"},
	{TypeTerminalResize, ClientRequest, "internal/terminal"},
	{TypeTerminalRename, ClientRequest, "internal/terminal"},
	{TypeTerminalClosed, ServerEvent, "internal/terminal"},
	{TypeTerminalTimeoutWarn, ServerEvent, "internal/terminal"},
	{TypeTerminalResync, ServerEvent, "internal/terminal"},
	{TypeTerminalInputReject, ServerEvent, "internal/terminal"},
	{TypeTerminalInputAck, ServerEvent, "internal/terminal"},
	{TypePromptHostKey, ServerEvent, "internal/terminal"},
	{TypePromptBanner, ServerEvent, "internal/terminal"},
	{TypePromptClosed, ServerEvent, "internal/terminal"},
	{TypePromptAnswer, ClientRequest, "internal/terminal"},

	{TypeHostsProfileList, ClientRequest, "internal/hosts"},
	{TypeHostsProfileSave, ClientRequest, "internal/hosts"},
	{TypeHostsProfileDelete, ClientRequest, "internal/hosts"},
	{TypeHostsProfileOrganize, ClientRequest, "internal/hosts"},
	{TypeHostsProfileMove, ClientRequest, "internal/hosts"},
	{TypeHostsJumpList, ClientRequest, "internal/hosts"},
	{TypeHostsJumpSave, ClientRequest, "internal/hosts"},
	{TypeHostsJumpDelete, ClientRequest, "internal/hosts"},
	{TypeHostsSOCKSList, ClientRequest, "internal/hosts"},
	{TypeHostsSOCKSSave, ClientRequest, "internal/hosts"},
	{TypeHostsSOCKSDelete, ClientRequest, "internal/hosts"},
	{TypeNotesGet, ClientRequest, "internal/hostops"},
	{TypeNotesSave, ClientRequest, "internal/hostops"},

	{TypeKeysList, ClientRequest, "internal/vault"},
	{TypeKeysUpload, ClientRequest, "internal/vault"},
	{TypeKeysRename, ClientRequest, "internal/vault"},
	{TypeKeysReplace, ClientRequest, "internal/vault"},
	{TypeKeysDelete, ClientRequest, "internal/vault"},

	{TypeSettingsTheme, ClientRequest, "internal/settings"},
	{TypeSettingsConfirmClose, ClientRequest, "internal/settings"},
	{TypeSettingsDisconnect, ClientRequest, "internal/settings"},

	// Area "gateway" (NW2, payload_gateway.go).
	{TypePromptInteractive, ServerEvent, "internal/ssh/gateway"},
	{TypePromptRespond, ClientRequest, "internal/ssh/gateway"},
	{TypeGatewaySetup, ServerEvent, "internal/ssh/gateway"},
	{TypeGatewayOutput, ServerEvent, "internal/ssh/gateway"},
	{TypeGatewayInput, ClientRequest, "internal/ssh/gateway"},
	{TypeGatewayAck, ClientRequest, "internal/ssh/gateway"},

	// Areas "insights", "inventory" and "herdr" (HO1, payload_insights.go).
	{TypeInsightsSample, ClientRequest, "internal/hostops"},
	{TypeInventorySample, ClientRequest, "internal/hostops"},
	{TypeHerdrSnapshot, ClientRequest, "internal/hostops"},

	// Area "hostops.discovery" (HO2, payload_discovery.go).
	{TypeDiscoveryPlatform, ServerEvent, "internal/hosts"},
	{TypeDiscoveryMaintenance, ServerEvent, "internal/hosts"},

	// Area "files" (FS1, payload_files.go).
	{TypeFilesList, ClientRequest, "internal/files"},
	{TypeFilesListCancel, ClientRequest, "internal/files"},
	{TypeFilesHome, ClientRequest, "internal/files"},
	{TypeFilesPreview, ClientRequest, "internal/files"},
	{TypeFilesImage, ClientRequest, "internal/files"},
	{TypeFilesEditOpen, ClientRequest, "internal/files"},
	{TypeFilesEditSave, ClientRequest, "internal/files"},
	{TypeFilesMkdir, ClientRequest, "internal/files"},
	{TypeFilesCreate, ClientRequest, "internal/files"},
	{TypeFilesRename, ClientRequest, "internal/files"},
	{TypeFilesDelete, ClientRequest, "internal/files"},
	{TypeFilesSourceClose, ClientRequest, "internal/files"},

	// The SFTP sources (FS2, payload_sftp.go).
	{TypeFilesQuickOpen, ClientRequest, "internal/files/sftp"},
	{TypeFilesQuickClose, ClientRequest, "internal/files/sftp"},
	{TypeFilesQuickCancel, ClientRequest, "internal/files/sftp"},
	{TypeFilesSessionProbe, ClientRequest, "internal/files/sftp"},
	{TypeFilesSessionDirectory, ClientRequest, "internal/files/sftp"},

	// Area "smb" (FS3, payload_smb.go).
	{TypeSMBShareList, ClientRequest, "internal/files/smb"},
	{TypeSMBShareSave, ClientRequest, "internal/files/smb"},
	{TypeSMBShareDelete, ClientRequest, "internal/files/smb"},
	{TypeSMBConnect, ClientRequest, "internal/files/smb"},
	{TypeSMBConnectCancel, ClientRequest, "internal/files/smb"},

	// Area "commands" (CM1, payload_commands.go).
	{TypeCommandsList, ClientRequest, "internal/commands"},
	{TypeCommandsAdd, ClientRequest, "internal/commands"},
	{TypeCommandsUpdate, ClientRequest, "internal/commands"},
	{TypeCommandsDelete, ClientRequest, "internal/commands"},
	{TypeCommandSetList, ClientRequest, "internal/commands"},
	{TypeCommandSetResolve, ClientRequest, "internal/commands"},
	{TypeCommandSetSave, ClientRequest, "internal/commands"},
	{TypeCommandSetDuplicate, ClientRequest, "internal/commands"},
	{TypeCommandSetDelete, ClientRequest, "internal/commands"},
	{TypeCommandSetConvert, ClientRequest, "internal/commands"},
	// Area "transfer" (TR1, payload_transfer.go).
	{TypeTransferPrepare, ClientRequest, "internal/transfer"},
	{TypeTransferCancel, ClientRequest, "internal/transfer"},
	{TypeTransferCopy, ClientRequest, "internal/transfer"},
	{TypeTransferProgress, ServerEvent, "internal/transfer"},
	{TypeTransferFinished, ServerEvent, "internal/transfer"},
}

// V1 returns the catalog of schema v1.
func V1() []MessageType { return slices.Clone(v1) }

// Lookup returns the catalog entry of name.
func Lookup(name string) (MessageType, bool) {
	i := slices.IndexFunc(v1, func(m MessageType) bool { return m.Name == name })
	if i < 0 {
		return MessageType{}, false
	}
	return v1[i], true
}

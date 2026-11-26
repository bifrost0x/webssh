package protocol

import "encoding/json/jsontext"

// Message types of the area "smb" (FS3): saved SMB share definitions and
// opening an SMB share as a file source. The Socket.IO events of today
// are mapped in static/js/realtime-shim-smb.js.
const (
	TypeSMBShareList     = "smb.share.list"
	TypeSMBShareSave     = "smb.share.save"
	TypeSMBShareDelete   = "smb.share.delete"
	TypeSMBConnect       = "smb.connect"
	TypeSMBConnectCancel = "smb.connect.cancel"
)

// The requests carry the members the page sends today
// (smb-source-dialog.js). Like the hosts.* requests every member is a raw
// JSON value, so the owner applies the rules of the Python release to
// presence and type; an absent member is a zero-length value.

// SMBShares is the result of smb.share.list: the saved definitions as
// stored, never with a password (smb_shares_list).
type SMBShares struct {
	SMBShares []jsontext.Value `json:"smb_shares"`
}

// SMBShareSave creates (without id) or updates one definition
// (save_smb_share).
type SMBShareSave struct {
	RequestID jsontext.Value `json:"request_id"`
	ID        jsontext.Value `json:"id"`
	Name      jsontext.Value `json:"name"`
	Host      jsontext.Value `json:"host"`
	Share     jsontext.Value `json:"share"`
	Domain    jsontext.Value `json:"domain"`
	Username  jsontext.Value `json:"username"`
}

// SMBShareSaved is the result of smb.share.save (smb_share_saved).
type SMBShareSaved struct {
	Share jsontext.Value `json:"share"`
}

// SMBShareDelete deletes one definition (delete_smb_share).
type SMBShareDelete struct {
	RequestID jsontext.Value `json:"request_id"`
	ShareID   jsontext.Value `json:"share_id"`
}

// SMBShareDeleted is the result of smb.share.delete (smb_share_deleted).
type SMBShareDeleted struct {
	ShareID string `json:"share_id"`
}

// SMBConnect opens a share as a file source (smb_quick_connect): with a
// password, or with a saved password (credential_id and, for a target
// the page has just confirmed, credential_target_token).
type SMBConnect struct {
	RequestID             jsontext.Value `json:"request_id"`
	Host                  jsontext.Value `json:"host"`
	Share                 jsontext.Value `json:"share"`
	Domain                jsontext.Value `json:"domain"`
	Username              jsontext.Value `json:"username"`
	Password              jsontext.Value `json:"password"`
	CredentialID          jsontext.Value `json:"credential_id"`
	CredentialTargetToken jsontext.Value `json:"credential_target_token"`
}

// SMBConnected is the result of smb.connect (smb_quick_connect_success).
type SMBConnected struct {
	FileSource SMBFileSource `json:"file_source"`
}

// SMBFileSource is the public descriptor of an SMB source
// (FileSourceDescriptor.to_public_dict).
type SMBFileSource struct {
	SourceID     string      `json:"source_id"`
	Kind         string      `json:"kind"`
	Label        string      `json:"label"`
	Endpoint     string      `json:"endpoint"`
	Protocol     string      `json:"protocol"`
	Capabilities []string    `json:"capabilities"`
	Ephemeral    bool        `json:"ephemeral"`
	Security     SMBSecurity `json:"security"`
	Access       SMBAccess   `json:"access"`
}

// SMBSecurity is the transport security the page shows.
type SMBSecurity struct {
	Encrypted       bool `json:"encrypted"`
	Signed          bool `json:"signed"`
	SecureNegotiate bool `json:"secure_negotiate"`
}

// SMBAccess are the rights probed at the share root: granted, denied or
// unknown.
type SMBAccess struct {
	List            string `json:"list"`
	CreateFile      string `json:"create_file"`
	CreateDirectory string `json:"create_directory"`
	DeleteChildren  string `json:"delete_children"`
}

// SMBConnectCancel cancels the attempt of request_id on this connection
// (smb_quick_connect_cancel).
type SMBConnectCancel struct {
	RequestID jsontext.Value `json:"request_id"`
}

package protocol

import "encoding/json/jsontext"

// Message types of the area "commands" (CM1): the command library (own
// commands and the built-in templates) and command sets. The Socket.IO
// events of today are mapped in static/js/realtime-shim-commands.js.
const (
	TypeCommandsList        = "commands.list"
	TypeCommandsAdd         = "commands.add"
	TypeCommandsUpdate      = "commands.update"
	TypeCommandsDelete      = "commands.delete"
	TypeCommandSetList      = "commands.set.list"
	TypeCommandSetResolve   = "commands.set.resolve"
	TypeCommandSetSave      = "commands.set.save"
	TypeCommandSetDuplicate = "commands.set.duplicate"
	TypeCommandSetDelete    = "commands.set.delete"
	TypeCommandSetConvert   = "commands.set.convert"
)

// CommandMaxPayload bounds the requests that carry a command or a set:
// a set of 64 steps of 16 KiB each, sent with escapes, and its parameters.
const CommandMaxPayload = 2 << 20

// The requests carry the members the page sends today
// (command-library.js, command-set-manager.js, session-command-launcher.js,
// automation.js). Like the hosts.* requests every member is a raw JSON
// value, so the owner applies the rules of the Python release to presence
// and type; an absent member is a zero-length value.

// CommandsList asks for the library (list_commands). OSFilter is a
// string or null.
type CommandsList struct {
	OSFilter jsontext.Value `json:"os_filter"`
}

// Commands is the result of commands.list (commands_list): the built-in
// templates, then the user's commands, each as stored with isSystem and
// userId.
type Commands struct {
	Commands []jsontext.Value `json:"commands"`
}

// CommandSave adds (commands.add, add_command) or updates
// (commands.update, update_command, with CommandID) one command.
type CommandSave struct {
	CommandID   jsontext.Value `json:"command_id"`
	Name        jsontext.Value `json:"name"`
	Command     jsontext.Value `json:"command"`
	Parameters  jsontext.Value `json:"parameters"`
	Description jsontext.Value `json:"description"`
	OS          jsontext.Value `json:"os"`
	Category    jsontext.Value `json:"category"`
}

// CommandSaved is the result of commands.add and commands.update
// (command_added, command_updated).
type CommandSaved struct {
	Command jsontext.Value `json:"command"`
}

// CommandDelete deletes one of the user's commands (delete_command).
type CommandDelete struct {
	CommandID jsontext.Value `json:"command_id"`
}

// CommandDeleted is the result of commands.delete (command_deleted).
type CommandDeleted struct {
	CommandID string `json:"command_id"`
}

// CommandSets is the result of commands.set.list (command_sets_list): the
// sets as stored, each with its resolved preview (resolved_command and
// sudo_resolved_command, or resolution_error and sudo_resolution_error).
type CommandSets struct {
	CommandSets []jsontext.Value `json:"command_sets"`
}

// CommandSetResolve resolves a parameterised set with values that are
// never stored (resolve_command_set_parameters).
type CommandSetResolve struct {
	CommandSetID jsontext.Value `json:"command_set_id"`
	Values       jsontext.Value `json:"values"`
	UseSudo      jsontext.Value `json:"use_sudo"`
}

// CommandSetResolved is the result of commands.set.resolve.
type CommandSetResolved struct {
	ResolvedCommand string `json:"resolved_command"`
}

// CommandSetSave creates (without ID) or updates one set
// (save_command_set).
type CommandSetSave struct {
	ID          jsontext.Value `json:"id"`
	Name        jsontext.Value `json:"name"`
	Description jsontext.Value `json:"description"`
	UseSudo     jsontext.Value `json:"use_sudo"`
	Parameters  jsontext.Value `json:"parameters"`
	Steps       jsontext.Value `json:"steps"`
}

// CommandSetSaved is the result of commands.set.save and
// commands.set.duplicate (command_set_saved).
type CommandSetSaved struct {
	CommandSet jsontext.Value `json:"command_set"`
}

// CommandSetRef names one set (duplicate_command_set,
// delete_command_set).
type CommandSetRef struct {
	CommandSetID jsontext.Value `json:"command_set_id"`
}

// CommandSetDeleted is the result of commands.set.delete
// (command_set_deleted).
type CommandSetDeleted struct {
	CommandSetID string `json:"command_set_id"`
}

// CommandSetConvert turns the free startup text of a saved host into a
// new set and assigns it to the host (convert_legacy_command_set).
type CommandSetConvert struct {
	ProfileID   jsontext.Value `json:"profile_id"`
	Name        jsontext.Value `json:"name"`
	Description jsontext.Value `json:"description"`
}

// CommandSetConverted is the result of commands.set.convert
// (command_set_converted): the new set and the saved host as the page
// shows it.
type CommandSetConverted struct {
	CommandSet jsontext.Value `json:"command_set"`
	Profile    jsontext.Value `json:"profile"`
}

package protocol_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

func members(v any) []string {
	var out []string
	t := reflect.TypeOf(v)
	for field := range t.Fields() {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// The members the frontend sends today. A member the browser adds is a
// contract change: the strict decoder refuses it.
func TestHostsPayloadMembers(t *testing.T) {
	for _, c := range []struct {
		payload any
		want    []string
		source  string
	}{
		{protocol.HostsProfileSave{}, []string{
			// profile-manager.js saveFromEditor, profile-launcher-utils.js herdrEditorPayload
			"name", "platform_icon", "group", "host", "port", "username", "auth_type", "key_id",
			"jump_host_id", "socks_proxy_id", "startup_mode", "herdr", "use_herdr", "use_tmux", "id",
			"greeting_platform", "command_set_id", "command_id", "parameters_override", "startup_commands",
			// accepted by upsert_profile beyond the form
			"favorite", "role_override",
		}, "save_profile"},
		{protocol.HostsProfileRef{}, []string{"profile_id"}, "delete_profile"},
		{protocol.HostsProfileOrganize{}, []string{"profile_id", "group", "favorite"}, "update_profile_organization"},
		{protocol.HostsProfileMove{}, []string{"profile_id", "expected_source_group", "target_group", "target_index",
			"confirm_source_group_removal"}, "move_profile"},
		{protocol.HostsJumpSave{}, []string{"name", "host", "port", "username", "auth_type", "key_id", "jump_host_id"}, "save_jump_host"},
		{protocol.HostsJumpRef{}, []string{"jump_host_id"}, "delete_jump_host"},
		{protocol.HostsSOCKSSave{}, []string{"name", "host", "port", "username", "auth_type", "remote_dns", "socks_proxy_id"}, "save_socks_proxy"},
		{protocol.HostsSOCKSRef{}, []string{"socks_proxy_id"}, "delete_socks_proxy"},
	} {
		want := slices.Sorted(slices.Values(c.want))
		if got := members(c.payload); !slices.Equal(got, want) {
			t.Errorf("%s: members %v, want %v", c.source, got, want)
		}
	}
}

func TestHostsPayloadsKeepPresenceAndRefuseUnknownMembers(t *testing.T) {
	var save protocol.HostsProfileSave
	if err := protocol.DecodePayload([]byte(`{"name":"n","key_id":null,"port":"22"}`), &save); err != nil {
		t.Fatal(err)
	}
	if string(save.KeyID) != "null" || string(save.Port) != `"22"` || len(save.Group) != 0 {
		t.Fatalf("presence lost: %q %q %q", save.KeyID, save.Port, save.Group)
	}
	for _, body := range []string{`{"tailscale_authorized":true}`, `{"Name":"n"}`, `{"name":"a","name":"b"}`, `{"group":{"a":1,"a":2}}`} {
		if err := protocol.DecodePayload([]byte(body), &save); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
}

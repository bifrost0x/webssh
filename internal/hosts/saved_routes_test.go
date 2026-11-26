package hosts

import (
	"encoding/json/jsontext"
	"testing"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/ssh/client"
)

func TestSavedRoutes(t *testing.T) {
	s := seeded(t, Legacy{JumpHosts: []jsontext.Value{
		v(`{"id":"jump-pw","name":"pw","host":"pw-jump.example","port":2200,"username":"u","auth_type":"password","key_id":null}`),
	}})
	hop, err := s.JumpHost(t.Context(), oracleUser, "2735737b-d93a-4e54-acd5-85b740b63526")
	want := client.Hop{Host: "bastion.golden.test", Port: 22, User: "jumper", Auth: client.Auth{KeyID: "d12ad3cd-eb07-4418-8967-a3169ba3de68"}}
	if err != nil || hop != want {
		t.Fatalf("JumpHost = %+v, %v", hop, err)
	}
	if hop, err := s.JumpHost(t.Context(), oracleUser, "jump-pw"); err != nil || hop != (client.Hop{Host: "pw-jump.example", Port: 2200, User: "u"}) {
		t.Fatalf("password jump host: %+v %v", hop, err)
	}
	if _, err := s.JumpHost(t.Context(), 4, "2735737b-d93a-4e54-acd5-85b740b63526"); code(err) != fault.NotFound {
		t.Fatalf("another user's jump host: %v", err)
	}
	proxy, err := s.SOCKSProxy(t.Context(), oracleUser, "45af77db-0c12-41d0-b28e-ea67984e5ebd")
	if err != nil || proxy != (client.SOCKS{Host: "socks.golden.test", Port: 1080, RemoteDNS: true}) {
		t.Fatalf("SOCKSProxy = %+v, %v", proxy, err)
	}
	if p, err := s.SOCKSProxy(t.Context(), oracleUser, "ae5c7232-6f7d-4457-bfca-0cc84e323aeb"); err != nil || p.Username == "" || p.Password != "" {
		t.Fatalf("proxy with login: %+v %v", p, err)
	}
	if _, err := s.SOCKSProxy(t.Context(), 4, "45af77db-0c12-41d0-b28e-ea67984e5ebd"); err == nil {
		t.Fatal("another user's proxy resolved")
	}
}

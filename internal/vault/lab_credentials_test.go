//go:build lab

package vault

import (
	"encoding/json/jsontext"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/principal/principaltest"
)

// A password saved and assigned through the vault signs in at the lab's
// sshd as pwuser; after the host changes the vault refuses to send it.
func TestLabSavedPasswordSignsIn(t *testing.T) {
	l := loadLab(t)
	svc := l.Services["ssh-modern"]
	raw, err := os.ReadFile(filepath.Join(l.RuntimeDir, "secrets", "ssh-pwuser"))
	if err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSpace(string(raw))
	r := newCredRig(t)
	p := principaltest.User(1)
	profile := jsontext.Value(`{"id":"lab","name":"Lab","host":"` + svc.Host + `","port":` + strconv.Itoa(svc.Port) +
		`,"username":"pwuser","auth_type":"password","key_id":null,"jump_host_id":null}`)
	r.stores.set(1, Records{Profiles: []jsontext.Value{profile}, SMB: true})
	if _, err := r.do(t, p, MethodCreate, "", map[string]any{"resource_id": "lab", "name": "Lab", "password": password, "confirm_target": true}); err != nil {
		t.Fatal(err)
	}
	target, found, err := r.svc.Resource(t.Context(), 1, "lab")
	if err != nil || !found {
		t.Fatal(err)
	}
	secret, err := r.svc.Password(t.Context(), 1, "lab", target)
	if err != nil {
		t.Fatal(err)
	}
	if err := passwordSignIn(svc.Host, svc.Port, svc.Fingerprints, string(secret)); err != nil {
		t.Fatalf("sign-in as pwuser: %v", err)
	}
	clear(secret)
	if err := passwordSignIn(svc.Host, svc.Port, svc.Fingerprints, "wrong-"+password); err == nil {
		t.Fatal("a wrong password signed in")
	}
	moved := jsontext.Value(strings.Replace(string(profile), `"username":"pwuser"`, `"username":"keyuser"`, 1))
	r.stores.set(1, Records{Profiles: []jsontext.Value{moved}, SMB: true})
	target, _, _ = r.svc.Resource(t.Context(), 1, "lab")
	if _, err := r.svc.Password(t.Context(), 1, "lab", target); fault.CodeOf(err) != fault.CredentialTargetChanged {
		t.Fatalf("changed target: %v", err)
	}
}

func passwordSignIn(host string, port int, fingerprints map[string]string, password string) error {
	known := make([]string, 0, len(fingerprints))
	for _, fp := range fingerprints {
		known = append(known, fp)
	}
	cfg := &ssh.ClientConfig{
		User: "pwuser",
		Auth: []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			if !slices.Contains(known, ssh.FingerprintSHA256(key)) {
				return errors.New("unknown lab host key")
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	c, err := ssh.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)), cfg)
	if err != nil {
		return err
	}
	return c.Close()
}

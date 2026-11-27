package smb

import (
	"testing"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/pyjson"
)

func TestPythonShareValidation(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.SecretFields {
		if got := secretField(c.In); got != c.Secret {
			t.Errorf("secret %q: %v, Python %v", c.In, got, c.Secret)
		}
	}
	for _, c := range v.Payloads {
		members, _ := pyjson.Members(c.In)
		var req SaveRequest
		secret := false
		for _, m := range members {
			switch m.Name {
			case "id":
				req.ID = m.Value
			case "name":
				req.Name = m.Value
			case "host":
				req.Host = m.Value
			case "share":
				req.Share = m.Value
			case "domain":
				req.Domain = m.Value
			case "username":
				req.Username = m.Value
			default:
				secret = secret || secretField(m.Name)
			}
		}
		if secret {
			// Refused by the strict request decoder (invalid_request)
			// before the rules run; Python refused it by name.
			if c.Validated != nil {
				t.Errorf("payload %s: secret member accepted by Python", c.In)
			}
			continue
		}
		if h, _ := pyjson.Get(c.In, "host"); h.Kind() == '0' {
			// fix: Python turned a number into a host name (str(7)).
			continue
		}
		f, _, err := validateSave(req)
		if (err == nil) != (c.Validated != nil) {
			t.Errorf("payload %s: err %v, Python %v", c.In, err, c.Error)
			continue
		}
		if err != nil && (c.Error == nil || err.(*fault.Error).Message != *c.Error) {
			t.Errorf("payload %s: %v, Python %q", c.In, err, *c.Error)
		}
		if err == nil && f != ShareFields(*c.Validated) {
			t.Errorf("payload %s: %+v, Python %+v", c.In, f, *c.Validated)
		}
	}
	for _, c := range v.Records {
		if got := validRecord(c.In); got != c.Valid {
			t.Errorf("record %s: %v, Python %v", c.In, got, c.Valid)
		}
	}
}

func TestPythonTimes(t *testing.T) {
	for _, c := range loadVectors(t).Times {
		if got := pythonUTC(time.Unix(0, c.UnixNS)); got != c.ISO {
			t.Errorf("%d: %q, Python %q", c.UnixNS, got, c.ISO)
		}
	}
}

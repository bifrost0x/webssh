package hostops

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"os"
	"slices"
	"strings"
	"testing"
)

// discovery_oracle.json is recorded from parse_network and parse_ports by
// testdata/discovery_oracle.py.
type discoveryOracle struct {
	Networks []struct {
		Value     string   `json:"value"`
		Network   string   `json:"network"`
		Addresses []string `json:"addresses"`
		Error     string   `json:"error"`
	} `json:"networks"`
	Ports []struct {
		Raw   string `json:"raw"`
		Ports []int  `json:"ports"`
		Error string `json:"error"`
	} `json:"ports"`
}

func readDiscoveryOracle(t *testing.T) discoveryOracle {
	t.Helper()
	raw, err := os.ReadFile("testdata/discovery_oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var o discoveryOracle
	if err := json.Unmarshal(raw, &o); err != nil {
		t.Fatal(err)
	}
	return o
}

func TestParseNetworkMatchesPython(t *testing.T) {
	o := readDiscoveryOracle(t)
	for _, c := range o.Networks {
		prefix, addrs, err := parseNetwork(c.Value)
		if strings.Contains(c.Value, "%") && c.Error == "" {
			// fix: a scoped address is refused (the scope never reached the probe).
			if err != errScanNetwork {
				t.Errorf("%q: scoped address accepted", c.Value)
			}
			continue
		}
		if c.Error != "" {
			if err == nil || string(err.(scanInputError)) != c.Error {
				t.Errorf("%q: %v, Python %s", c.Value, err, c.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v, Python %s", c.Value, err, c.Network)
			continue
		}
		got := make([]string, len(addrs))
		for i, a := range addrs {
			got[i] = a.String()
		}
		if prefix.String() != c.Network || !slices.Equal(got, c.Addresses) {
			t.Errorf("%q: %s %d addresses, Python %s %d", c.Value, prefix, len(got), c.Network, len(c.Addresses))
		}
	}
}

func TestParsePortsMatchesPython(t *testing.T) {
	for _, c := range readDiscoveryOracle(t).Ports {
		got, err := parsePorts(jsontext.Value(c.Raw))
		if c.Error != "" {
			if err == nil {
				t.Errorf("%s: %v accepted, Python refused", c.Raw, got)
			}
			continue
		}
		if err != nil || !slices.Equal(got, c.Ports) {
			t.Errorf("%s: %v %v, Python %v", c.Raw, got, err, c.Ports)
		}
	}
	if got, err := parsePorts(nil); err != nil || !slices.Equal(got, []int{22}) {
		t.Errorf("absent ports: %v %v", got, err)
	}
}

func FuzzParseNetwork(f *testing.F) {
	for _, s := range []string{"10.0.0.0/24", "2001:db8::/120", "10.0.0.5/0.0.0.255", "::ffff:1.2.3.4"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		prefix, addrs, err := parseNetwork(s)
		if err != nil {
			return
		}
		if len(addrs) == 0 || len(addrs) > MaxScanAddresses {
			t.Fatalf("%q: %d addresses", s, len(addrs))
		}
		for _, a := range addrs {
			if !prefix.Contains(a) {
				t.Fatalf("%q: %s outside %s", s, a, prefix)
			}
		}
	})
}

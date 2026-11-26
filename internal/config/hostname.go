package config

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/bifrost0x/webssh/internal/idna2003"
)

var errHost = errors.New("invalid host")

// idnaASCII is name.encode('idna').decode('ascii').lower() of Python.
func idnaASCII(name string) (string, error) {
	encoded, err := idna2003.Encode(name)
	if err != nil {
		return "", errHost
	}
	return strings.ToLower(encoded), nil
}

// validDNSName is the label check shared by the Python parsers.
func validDNSName(canonical string) bool {
	if canonical == "" || len(canonical) > 253 {
		return false
	}
	for label := range strings.SplitSeq(canonical, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			c := label[i]
			if !(c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
				return false
			}
		}
	}
	return true
}

// tailscaleTarget is parse_tailscale_ssh_target of config.py: one
// canonical host and port.
func tailscaleTarget(raw string) (host string, port int, err error) {
	value := pyStrip(raw)
	if value == "" || runeLen(value) > 261 || strings.Contains(value, "%") {
		return "", 0, errHost
	}
	host, port = value, 22
	if strings.HasPrefix(value, "[") {
		closing := strings.IndexByte(value, ']')
		if closing < 0 {
			return "", 0, errHost
		}
		host = value[1:closing]
		if suffix := value[closing+1:]; suffix != "" {
			portText := ""
			if strings.HasPrefix(suffix, ":") {
				portText = suffix[1:]
			}
			if !isASCIIDigits(portText) || len(portText) > 5 {
				return "", 0, errHost
			}
			port, _ = strconv.Atoi(portText)
		}
		a, err := pyIPAddress(host)
		if err != nil || a.is4 {
			return "", 0, errHost
		}
		host = a.String()
	} else {
		if strings.ContainsAny(value, "[]") {
			return "", 0, errHost
		}
		if strings.Count(value, ":") == 1 {
			h, p, _ := strings.Cut(value, ":")
			if isASCIIDigits(p) && len(p) <= 5 {
				host = h
				port, _ = strconv.Atoi(p)
			}
		}
		host = strings.TrimRight(host, ".")
		if a, err := pyIPAddress(host); err == nil {
			host = a.String()
		} else {
			if strings.Contains(host, ":") {
				return "", 0, errHost
			}
			canonical, err := idnaASCII(host)
			if err != nil {
				return "", 0, err
			}
			if !validDNSName(canonical) {
				return "", 0, errHost
			}
			host = canonical
		}
	}
	if port < 1 || port > 65535 {
		return "", 0, errHost
	}
	return host, port, nil
}

// remoteDNSAllowlist is parse_remote_dns_allowlist of config.py.
func remoteDNSAllowlist(raw, name string) ([]string, error) {
	var names []string
	for part := range strings.SplitSeq(raw, ",") {
		entry := pyStrip(part)
		if entry == "" {
			continue
		}
		if strings.ContainsAny(entry, ":[]%") {
			return nil, exactDNSError(name)
		}
		canonical, _, err := tailscaleTarget(entry)
		if err != nil {
			return nil, exactDNSError(name)
		}
		if _, err := pyIPAddress(canonical); err == nil {
			return nil, exactDNSError(name)
		}
		if !slices.Contains(names, canonical) {
			names = append(names, canonical)
		}
	}
	return names, nil
}

func exactDNSError(name string) error {
	return configError(name, "CONFIGURATION ERROR: "+name+" accepts only exact DNS hostnames")
}

// smbTarget is _canonical_smb_target of validate_security_config.
func smbTarget(raw string) (string, error) {
	value := pyStrip(raw)
	if value == "" || strings.ContainsAny(value, "/\\@*?#") {
		return "", errHost
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = value[1 : len(value)-1]
	}
	value = strings.TrimRight(value, ".")
	if a, err := pyIPAddress(value); err == nil {
		return a.String(), nil
	}
	if strings.ContainsAny(value, ":[]") {
		return "", errHost
	}
	if value == "" {
		// Python encodes "" to "" and then finds one empty label.
		return "", errHost
	}
	canonical, err := idnaASCII(value)
	if err != nil {
		return "", err
	}
	if !validDNSName(canonical) {
		return "", errHost
	}
	return canonical, nil
}

package client

import (
	"slices"

	"golang.org/x/crypto/ssh"
)

// hostKeyOrder is the preference for hosts without stored trust. It is the
// order paramiko used, so first contacts store the same key type as before.
// Certificates and ML-DSA are left out: the trust store cannot hold them.
var hostKeyOrder = []string{
	ssh.KeyAlgoED25519,
	ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// legacyAlgorithms are offered only for a hop with the legacy setting: an
// opt-in per host on new installations, the setting the migration writes
// for existing ones (D-01). They are appended, so they have the lowest
// priority and a server that supports anything better gets that.
// diffie-hellman-group1-sha1, DSA, aes192-cbc, aes256-cbc and hmac-md5 are
// never offered (x/crypto has no CBC beyond aes128 and no MD5).
var legacyAlgorithms = ssh.Algorithms{
	KeyExchanges: []string{ssh.InsecureKeyExchangeDH14SHA1, ssh.InsecureKeyExchangeDHGEXSHA1},
	Ciphers:      []string{ssh.InsecureCipherAES128CBC, ssh.InsecureCipherTripleDESCBC},
	MACs:         []string{ssh.HMACSHA1},
	HostKeys:     []string{ssh.KeyAlgoRSA},
}

// Algorithms is the negotiation set for one hop. The package defaults of
// x/crypto/ssh still contain SHA-1 key exchange, ssh-rsa host keys and
// hmac-sha1-96, so the lists are always set explicitly.
func Algorithms(legacy bool) ssh.Algorithms {
	a := ssh.SupportedAlgorithms()
	a.HostKeys = slices.Clone(hostKeyOrder)
	a.MACs = slices.DeleteFunc(a.MACs, func(m string) bool { return slices.Contains(legacyAlgorithms.MACs, m) })
	if legacy {
		a.MACs = append(a.MACs, legacyAlgorithms.MACs...)
		a.KeyExchanges = append(a.KeyExchanges, legacyAlgorithms.KeyExchanges...)
		a.Ciphers = append(a.Ciphers, legacyAlgorithms.Ciphers...)
		a.HostKeys = append(a.HostKeys, legacyAlgorithms.HostKeys...)
	}
	return a
}

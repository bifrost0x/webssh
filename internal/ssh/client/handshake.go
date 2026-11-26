package client

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Banner limits: the Python release showed at most 16 Ki characters.
const (
	maxBannerChars = 16 << 10
	maxBannerBytes = 4 * maxBannerChars
)

// handshake runs key exchange, the host-key check, authentication and the
// banner decision on conn. conn is closed on failure.
func (d *Dialer) handshake(ctx context.Context, conn net.Conn, owner int64, h hop, ix Interaction, variant func(AuthRequest) ssh.ClientAuthCallback) (*ssh.Client, error) {
	hctx, cancel := context.WithTimeout(ctx, d.InteractionTimeout)
	defer cancel()
	stopClose := context.AfterFunc(hctx, func() { _ = conn.Close() })
	wd := startWatchdog(conn, d.HandshakeTimeout)

	algos := Algorithms(h.Legacy)
	hostKeyAlgos, err := d.HostKeys.Preferred(hctx, owner, h.Host, h.Port, algos.HostKeys)
	if err != nil {
		wd.stop()
		stopClose()
		_ = conn.Close()
		return nil, fail(hctx, h.role, false, err)
	}
	var banner strings.Builder
	plan := &authPlan{ctx: hctx, password: h.Auth.Password, signer: h.signer, legacy: h.Legacy, attended: ix != nil}
	if ch, ok := ix.(Challenger); ok {
		plan.ask = func(name, instruction string, questions []string, echos []bool) ([]string, error) {
			return askUser(hctx, wd, ch, h, name, instruction, questions, echos)
		}
	}
	authCallback := plan.next
	if variant != nil {
		signer := h.signer
		if signer != nil {
			if signer, err = restrictSigner(signer, h.Legacy); err != nil {
				wd.stop()
				stopClose()
				_ = conn.Close()
				return nil, fail(hctx, h.role, false, err)
			}
		}
		authCallback = variant(AuthRequest{Ctx: hctx, Role: h.role, Host: h.Host, Port: h.Port, User: h.User,
			Password: h.Auth.Password, Signer: signer, Pause: wd.pause})
	}
	cfg := &ssh.ClientConfig{
		KeyExchanges: algos.KeyExchanges, Ciphers: algos.Ciphers, MACs: algos.MACs,
		RekeyThreshold:    d.RekeyThreshold,
		User:              h.User,
		HostKeyAlgorithms: hostKeyAlgos,
		HostKeyCallback: func() ssh.HostKeyCallback {
			check := pinnedHostKey(func(key ssh.PublicKey) error { return d.checkHostKey(hctx, wd, owner, h, ix, key) })
			return func(_ string, _ net.Addr, key ssh.PublicKey) error { return check(key) }
		}(),
		BannerCallback: func(message string) error {
			if banner.Len()+len(message) <= maxBannerBytes {
				banner.WriteString(message)
			}
			return nil
		},
		AuthCallback: authCallback,
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, joinHostPort(h.Host, h.Port), cfg)
	timedOut := wd.stop()
	if !stopClose() && err == nil {
		// The context ended in the moment the handshake finished.
		_ = c.Close()
		return nil, fail(hctx, h.role, false, hctx.Err())
	}
	if err != nil {
		_ = conn.Close()
		return nil, fail(hctx, h.role, timedOut, err)
	}
	client := ssh.NewClient(c, chans, reqs)
	if text := sanitizeBanner(banner.String()); text != "" {
		if err := d.decideBanner(hctx, h, ix, text); err != nil {
			_ = client.Close()
			return nil, fail(hctx, h.role, false, err)
		}
	}
	return client, nil
}

// pinnedHostKey runs first for the key of the first key exchange and
// remembers it once it is accepted. A re-key repeats the host-key callback
// long after the handshake context ended: then only the same key is
// accepted, without the store and without a prompt.
func pinnedHostKey(first func(ssh.PublicKey) error) func(ssh.PublicKey) error {
	var mu sync.Mutex
	var pinned []byte
	return func(key ssh.PublicKey) error {
		mu.Lock()
		defer mu.Unlock()
		if pinned != nil {
			if bytes.Equal(pinned, key.Marshal()) {
				return nil
			}
			return fault.New(fault.HostKeyChanged, "")
		}
		if err := first(key); err != nil {
			return err
		}
		pinned = key.Marshal()
		return nil
	}
}

// checkHostKey is the host-key callback of one hop. Only a host without any
// trust is offered to the user; a changed or revoked key is refused at
// once. Without an Interaction nothing is trusted on first use.
func (d *Dialer) checkHostKey(ctx context.Context, wd *watchdog, owner int64, h hop, ix Interaction, key ssh.PublicKey) error {
	known, err := d.HostKeys.Known(ctx, owner, h.Host, h.Port, key)
	switch {
	case err != nil:
		return err
	case known:
		return nil
	case ix == nil:
		return fault.New(fault.HostKeyNotAccepted, "")
	}
	resume := wd.pause()
	accepted, err := ix.HostKey(ctx, HostKeyPrompt{
		Role: h.role, Host: h.Host, Port: h.Port,
		KeyType: key.Type(), Fingerprint: ssh.FingerprintSHA256(key),
	})
	resume()
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case err != nil:
		return fault.Wrap(fault.HostKeyNotAccepted, err, "")
	case !accepted:
		return fault.New(fault.HostKeyNotAccepted, "")
	}
	return d.HostKeys.Record(ctx, owner, h.Host, h.Port, key)
}

// decideBanner asks the user to accept a pre-authentication banner before
// any channel is opened. Without an Interaction the banner is refused.
func (d *Dialer) decideBanner(ctx context.Context, h hop, ix Interaction, text string) error {
	if ix == nil {
		return errBanner
	}
	ok, err := ix.Banner(ctx, BannerPrompt{Role: h.role, Host: h.Host, Port: h.Port, Banner: text})
	switch {
	case ctx.Err() != nil:
		return ctx.Err()
	case err != nil || !ok:
		return errBanner
	}
	return nil
}

// sanitizeBanner makes a remote banner safe to show, as the Python release
// did: each invalid UTF-8 byte replaced (ranging over the string yields
// U+FFFD for it), line ends normalized, only printable
// characters, tabs and newlines kept, at most 16 Ki characters, stripped.
func sanitizeBanner(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	var b strings.Builder
	n := 0
	for _, r := range raw {
		if n == maxBannerChars {
			break
		}
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			b.WriteRune(r)
			n++
		}
	}
	return pyStrip(b.String())
}

// pyStrip mirrors Python's str.strip() without arguments.
func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case 0x1c, 0x1d, 0x1e, 0x1f:
			return true
		}
		return unicode.IsSpace(r) || unicode.Is(unicode.Zs, r)
	})
}

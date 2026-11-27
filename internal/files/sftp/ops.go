package sftp

import (
	"context"
	"encoding/binary"
)

// Extensions of OpenSSH the backend uses.
const (
	extPosixRename = "posix-rename@openssh.com"
	extLsetstat    = "lsetstat@openssh.com"
	extLimits      = "limits@openssh.com"
)

// statusError is an SSH_FXP_STATUS other than OK: the server answered.
type statusError struct{ code uint32 }

func (e *statusError) Error() string { return "sftp status " + statusName(e.code) }

func statusName(c uint32) string {
	switch c {
	case fxEOF:
		return "eof"
	case fxNoSuchFile:
		return "no such file"
	case fxPermissionDenied:
		return "permission denied"
	case fxFailure:
		return "failure"
	case fxBadMessage:
		return "bad message"
	case fxOpUnsupported:
		return "unsupported"
	}
	return "other"
}

func isStatus(err error, code uint32) bool {
	se, ok := err.(*statusError)
	return ok && se.code == code
}

// wire is the own request layer on the router.
type wire struct{ r *router }

// do sends a request and returns its reply. A status reply is turned into
// nil (OK) or a *statusError, unless the caller expects another type.
func (w wire) do(ctx context.Context, want byte, build func(id uint32) *encoder) (*decoder, error) {
	rep, err := w.r.call(ctx, build)
	if err != nil {
		return nil, err
	}
	d := &decoder{b: rep.body}
	if rep.typ == fxpStatus {
		st := d.status(w.r.lim)
		if err := d.end(); err != nil {
			w.r.fail(err)
			return nil, &transportError{sent: true, err: err}
		}
		if st.code == fxOK && want == fxpStatus {
			return d, nil
		}
		if st.code == fxOK {
			w.r.fail(errMalformed)
			return nil, &transportError{sent: true, err: errMalformed}
		}
		return nil, &statusError{code: st.code}
	}
	if rep.typ != want {
		w.r.fail(errMalformed)
		return nil, &transportError{sent: true, err: errMalformed}
	}
	return d, nil
}

// finish checks the rest of a reply; a malformed reply closes the channel.
func (w wire) finish(d *decoder) error {
	if err := d.end(); err != nil {
		w.r.fail(err)
		return &transportError{sent: true, err: err}
	}
	return nil
}

func (w wire) statusOnly(ctx context.Context, build func(id uint32) *encoder) error {
	_, err := w.do(ctx, fxpStatus, build)
	return err
}

func (w wire) pathAttrs(ctx context.Context, typ byte, p string) (attrs, error) {
	d, err := w.do(ctx, fxpAttrs, func(id uint32) *encoder { return newPacket(typ, id).str(p) })
	if err != nil {
		return attrs{}, err
	}
	a := d.attrs(w.r.lim)
	return a, w.finish(d)
}

func (w wire) lstat(ctx context.Context, p string) (attrs, error) {
	return w.pathAttrs(ctx, fxpLstat, p)
}

func (w wire) stat(ctx context.Context, p string) (attrs, error) {
	return w.pathAttrs(ctx, fxpStat, p)
}

// resolve asks the server for the canonical form of p (REALPATH),
// links included.
func (w wire) resolve(ctx context.Context, p string) (string, error) {
	d, err := w.do(ctx, fxpName, func(id uint32) *encoder { return newPacket(fxpRealpath, id).str(p) })
	if err != nil {
		return "", err
	}
	if d.u32() != 1 {
		w.r.fail(errMalformed)
		return "", &transportError{sent: true, err: errMalformed}
	}
	name := d.bytesN(w.r.lim.maxName)
	d.bytesN(w.r.lim.maxName)
	d.attrs(w.r.lim)
	if err := w.finish(d); err != nil {
		return "", err
	}
	return string(name), nil
}

func (w wire) opendir(ctx context.Context, p string) (string, error) {
	d, err := w.do(ctx, fxpHandle, func(id uint32) *encoder { return newPacket(fxpOpendir, id).str(p) })
	if err != nil {
		return "", err
	}
	h := d.handle(w.r.lim)
	return h, w.finish(d)
}

// readdir returns the next batch of a directory; eof reports the end.
func (w wire) readdir(ctx context.Context, h string) ([]nameEntry, bool, error) {
	d, err := w.do(ctx, fxpName, func(id uint32) *encoder { return newPacket(fxpReaddir, id).str(h) })
	if isStatus(err, fxEOF) {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	names := d.names(w.r.lim)
	return names, false, w.finish(d)
}

func (w wire) closeHandle(ctx context.Context, h string) error {
	return w.statusOnly(ctx, func(id uint32) *encoder { return newPacket(fxpClose, id).str(h) })
}

func (w wire) mkdir(ctx context.Context, p string) error {
	return w.statusOnly(ctx, func(id uint32) *encoder { return newPacket(fxpMkdir, id).str(p).noAttrs() })
}

func (w wire) rmdir(ctx context.Context, p string) error {
	return w.statusOnly(ctx, func(id uint32) *encoder { return newPacket(fxpRmdir, id).str(p) })
}

func (w wire) remove(ctx context.Context, p string) error {
	return w.statusOnly(ctx, func(id uint32) *encoder { return newPacket(fxpRemove, id).str(p) })
}

// rename is the v3 rename, which OpenSSH never lets replace a target.
func (w wire) rename(ctx context.Context, from, to string) error {
	return w.statusOnly(ctx, func(id uint32) *encoder { return newPacket(fxpRename, id).str(from).str(to) })
}

func (w wire) posixRename(ctx context.Context, from, to string) error {
	return w.statusOnly(ctx, func(id uint32) *encoder {
		return newPacket(fxpExtended, id).str(extPosixRename).str(from).str(to)
	})
}

// lsetstat sets the permission bits of p itself, never of a link target.
func (w wire) lsetstat(ctx context.Context, p string, perm uint32) error {
	return w.statusOnly(ctx, func(id uint32) *encoder {
		return newPacket(fxpExtended, id).str(extLsetstat).str(p).mode(perm)
	})
}

// serverLimits are the answers of limits@openssh.com; zero means unknown.
type serverLimits struct{ packet, read, write, handles uint64 }

func (w wire) limits(ctx context.Context) (serverLimits, error) {
	rep, err := w.r.call(ctx, func(id uint32) *encoder { return newPacket(fxpExtended, id).str(extLimits) })
	if err != nil {
		return serverLimits{}, err
	}
	if rep.typ != fxpExtReply || len(rep.body) < 32 {
		return serverLimits{}, &statusError{code: fxOpUnsupported}
	}
	b := rep.body
	return serverLimits{
		packet:  binary.BigEndian.Uint64(b[0:]),
		read:    binary.BigEndian.Uint64(b[8:]),
		write:   binary.BigEndian.Uint64(b[16:]),
		handles: binary.BigEndian.Uint64(b[24:]),
	}, nil
}

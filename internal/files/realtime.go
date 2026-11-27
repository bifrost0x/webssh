package files

import (
	"context"
	"encoding/base64"
	"encoding/json/jsontext"
	"path"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Payload bounds of files.*: control requests carry paths of up to 4096
// bytes, escaped; a save carries the editor text, escaped.
const maxControlPayload = 32 << 10

// Routes returns the realtime routes of files.* (docs/architecture/
// m2-contracts.md, "Message types (files)").
func (s *Service) Routes() []protocol.Route {
	spec := func(timeout time.Duration, mutates bool) protocol.Spec {
		return protocol.Spec{Async: true, Timeout: timeout, Mutates: mutates, MaxPayload: maxControlPayload}
	}
	save := spec(120*time.Second, true)
	// The editor text, JSON-escaped; an editor limit beyond 128 MiB is not
	// carried by one realtime message.
	save.MaxPayload = int(6*min(s.opts.MaxEditorBytes, 128<<20) + 64<<10)
	return []protocol.Route{
		route(s, protocol.TypeFilesList, spec(60*time.Second, false), s.listRoute),
		route(s, protocol.TypeFilesListCancel, spec(30*time.Second, false), s.cancelRoute),
		route(s, protocol.TypeFilesHome, spec(30*time.Second, false), s.homeRoute),
		route(s, protocol.TypeFilesPreview, spec(60*time.Second, false), s.previewRoute),
		route(s, protocol.TypeFilesImage, spec(60*time.Second, false), s.imageRoute),
		route(s, protocol.TypeFilesEditOpen, spec(60*time.Second, false), s.editOpenRoute),
		route(s, protocol.TypeFilesEditSave, save, s.saveRoute),
		route(s, protocol.TypeFilesMkdir, spec(60*time.Second, true), s.mkdirRoute),
		route(s, protocol.TypeFilesCreate, spec(60*time.Second, true), s.createRoute),
		route(s, protocol.TypeFilesRename, spec(60*time.Second, true), s.renameRoute),
		route(s, protocol.TypeFilesDelete, spec(300*time.Second, true), s.deleteRoute),
		route(s, protocol.TypeFilesSourceClose, spec(30*time.Second, true), s.sourceCloseRoute),
	}
}

// route is protocol.Handle with the byte budget of file requests charged
// before the payload is decoded. A save charges its body to the editor
// budget instead (Save), so only a fixed amount here.
func route[Req, Resp any](s *Service, typ string, spec protocol.Spec, h func(context.Context, Caller, Req) (Resp, error)) protocol.Route {
	inner := protocol.Handle(typ, spec, func(ctx context.Context, peer protocol.Peer, req Req) (Resp, error) {
		return h(ctx, Caller{P: peer.Principal(), Peer: peer.ID()}, req)
	})
	return protocol.Route{Type: typ, Spec: spec, Run: func(ctx context.Context, peer protocol.Peer, p jsontext.Value) (any, error) {
		n := len(p)
		if typ == protocol.TypeFilesEditSave {
			n = 0
		}
		if err := s.ChargeRequest(Caller{P: peer.Principal(), Peer: peer.ID()}, n); err != nil {
			return nil, err
		}
		return inner.Run(ctx, peer, p)
	}}
}

// requireRef checks the members every file request carries.
func requireRef(r protocol.FileRef) error {
	if r.SourceID == "" || !ValidRequestID(r.RequestID) {
		return fault.New(fault.InvalidRequest, "Source ID and request ID required.")
	}
	return nil
}

func (s *Service) listRoute(ctx context.Context, c Caller, rq protocol.FilesList) (*protocol.FilesListing, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	page, err := s.List(ctx, c, rq.SourceID, rq.RequestID, rq.RemotePath, rq.Cursor)
	if err != nil {
		return nil, err
	}
	out := &protocol.FilesListing{FileRef: rq.FileRef, Path: rq.RemotePath, Files: make([]protocol.FileEntry, 0, len(page.Entries))}
	for _, e := range page.Entries {
		out.Files = append(out.Files, wireEntry(e))
	}
	if page.Next != "" {
		out.NextCursor = &page.Next
	}
	return out, nil
}

func wireEntry(e Entry) protocol.FileEntry {
	var modified float64
	if !e.ModTime.IsZero() {
		modified = float64(e.ModTime.UnixNano()) / 1e9
	}
	return protocol.FileEntry{Name: e.Name, Size: e.Size, Mode: e.Mode, IsDir: e.IsDir, IsSymlink: e.IsSymlink, Modified: modified}
}

func (s *Service) cancelRoute(_ context.Context, c Caller, rq protocol.FilesListCancel) (*protocol.Empty, error) {
	if requireRef(rq.FileRef) == nil {
		s.CancelListing(c, rq.SourceID, rq.Cursor, rq.ListingRequestID)
	}
	return &protocol.Empty{}, nil
}

func (s *Service) homeRoute(ctx context.Context, c Caller, rq protocol.FileRef) (*protocol.FilesPath, error) {
	if err := requireRef(rq); err != nil {
		return nil, err
	}
	home, err := s.Home(ctx, c, rq.SourceID)
	if err != nil {
		return nil, err
	}
	return &protocol.FilesPath{FileRef: rq, Path: home}, nil
}

func (s *Service) previewRoute(ctx context.Context, c Caller, rq protocol.FilesPreview) (*protocol.FilesPreviewData, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	pv, err := s.Preview(ctx, c, PreviewRequest{SourceID: rq.SourceID, Path: rq.Path, Offset: rq.Offset, MaxBytes: rq.MaxBytes, TailLines: rq.TailLines})
	if err != nil {
		return nil, err
	}
	out := &protocol.FilesPreviewData{
		FileRef: rq.FileRef, Path: rq.Path, Filename: path.Base(rq.Path), Size: pv.Size, ReadSize: pv.ReadSize,
		Truncated: pv.Truncated, IsBinary: pv.Binary, Offset: pv.Offset, Encoding: string(pv.Encoding),
	}
	if !pv.Binary {
		out.Content = &pv.Text
	}
	return out, nil
}

func (s *Service) imageRoute(ctx context.Context, c Caller, rq protocol.FilesImage) (*protocol.FilesImageData, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	if !rq.ForPreview {
		return nil, fault.New(fault.InvalidRequest, "Missing required fields for binary download.")
	}
	data, err := s.Image(ctx, c, rq.SourceID, rq.RemotePath)
	if err != nil {
		return nil, err
	}
	out := &protocol.FilesImageData{
		FileRef: rq.FileRef, Path: rq.RemotePath, Filename: path.Base(rq.RemotePath),
		FileData: base64.StdEncoding.EncodeToString(data), Size: int64(len(data)), ForPreview: true, Encoding: "base64",
	}
	return offload(s, c, out, func(token string) *protocol.FilesImageData {
		return &protocol.FilesImageData{FileRef: rq.FileRef, Path: rq.RemotePath, Filename: out.Filename, Size: out.Size,
			ForPreview: true, Encoding: "base64", Handoff: token}
	})
}

func (s *Service) editOpenRoute(ctx context.Context, c Caller, rq protocol.FilesEditOpen) (*protocol.FilesEditData, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	doc, err := s.OpenEdit(ctx, c, rq.SourceID, rq.Path)
	if err != nil {
		return nil, err
	}
	out := &protocol.FilesEditData{
		FileRef: rq.FileRef, Path: rq.Path, Filename: path.Base(rq.Path), Content: doc.Text, Size: doc.Size,
		Encoding: string(doc.Encoding), Newline: string(doc.Newline), Revision: doc.Revision,
		OriginalBytes: base64.StdEncoding.EncodeToString(doc.Original), Endpoint: doc.Endpoint,
	}
	return offload(s, c, out, func(token string) *protocol.FilesEditData {
		return &protocol.FilesEditData{FileRef: rq.FileRef, Path: rq.Path, Filename: out.Filename, Size: out.Size, Handoff: token}
	})
}

func (s *Service) saveRoute(ctx context.Context, c Caller, rq protocol.FilesEditSave) (*protocol.FilesSaved, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	out, err := s.Save(ctx, c, SaveRequest{
		SourceID: rq.SourceID, Path: rq.Path, Content: rq.Content, Encoding: rq.Encoding, Newline: rq.Newline,
		ExpectedRevision: rq.ExpectedRevision, Strategy: rq.ReplaceStrategy, Challenge: rq.SaveChallenge,
	})
	if err != nil {
		return nil, err
	}
	return &protocol.FilesSaved{FileRef: rq.FileRef, Path: rq.Path, Revision: out.Revision, WarningCode: out.Warning, RecoveryLeaves: out.RecoveryLeaves}, nil
}

func (s *Service) mkdirRoute(ctx context.Context, c Caller, rq protocol.FilesMkdir) (*protocol.FilesPath, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	p, err := s.Mkdir(ctx, c, rq.SourceID, rq.RemotePath)
	if err != nil {
		return nil, err
	}
	return &protocol.FilesPath{FileRef: rq.FileRef, Path: p}, nil
}

func (s *Service) createRoute(ctx context.Context, c Caller, rq protocol.FilesCreate) (*protocol.FilesCreated, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	p, err := s.CreateFile(ctx, c, rq.SourceID, rq.ParentPath, rq.Name)
	if err != nil {
		return nil, err
	}
	return &protocol.FilesCreated{FileRef: rq.FileRef, Path: p}, nil
}

func (s *Service) renameRoute(ctx context.Context, c Caller, rq protocol.FilesRename) (*protocol.FilesRenamed, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, errMove
	}
	if err := s.Rename(ctx, c, rq.SourceID, rq.OldPath, rq.NewPath); err != nil {
		return nil, err
	}
	return &protocol.FilesRenamed{FileRef: rq.FileRef, OldPath: rq.OldPath, NewPath: rq.NewPath}, nil
}

func (s *Service) deleteRoute(ctx context.Context, c Caller, rq protocol.FilesDelete) (*protocol.FilesPath, error) {
	if err := requireRef(rq.FileRef); err != nil {
		return nil, err
	}
	if err := s.Delete(ctx, c, rq.SourceID, rq.Path); err != nil {
		return nil, err
	}
	return &protocol.FilesPath{FileRef: rq.FileRef, Path: rq.Path}, nil
}

func (s *Service) sourceCloseRoute(_ context.Context, c Caller, rq protocol.FilesSourceClose) (*protocol.FilesSourceClosed, error) {
	if err := s.CloseSource(c, rq.SourceID); err != nil {
		return nil, err
	}
	return &protocol.FilesSourceClosed{SourceID: rq.SourceID}, nil
}

// PublicSource is the file_source descriptor the page receives for an open
// source (FileSourceDescriptor.to_public_dict of the Python release).
func PublicSource(d Descriptor, c Capabilities) protocol.FileSource {
	access := d.Access
	sec := map[string]bool{}
	switch d.Kind {
	case KindSFTP:
		sec["host_key_verified"] = d.Security.HostKeyVerified
	case KindSMB:
		sec["encrypted"], sec["secure_negotiate"], sec["signed"] = d.Security.Encrypted, d.Security.SecureNegotiate, d.Security.Signed
	}
	acc := map[string]string{}
	if access != nil {
		acc["list"], acc["create_file"] = access.List, access.CreateFile
		acc["create_directory"], acc["delete_children"] = access.CreateDirectory, access.DeleteChildren
	}
	caps := c.Ops.Names()
	if caps == nil {
		caps = []string{}
	}
	return protocol.FileSource{
		SourceID: d.SourceID, Kind: string(d.Kind), Label: d.Label, Endpoint: d.Endpoint, Protocol: d.Protocol,
		Capabilities: caps, Ephemeral: d.Ephemeral, Security: sec, Access: acc,
	}
}

package smb

import (
	"context"
	"time"

	"github.com/bifrost0x/webssh/internal/fault"
	"github.com/bifrost0x/webssh/internal/files"
	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Rate-limit buckets of the Python handlers (SMB_SHARE_LIST_RATELIMIT,
// SMB_SHARE_MUTATION_RATELIMIT, SMB_CONNECT_RATELIMIT).
const (
	RateShareList     = "smb_share_list"
	RateShareMutation = "smb_share_mutation"
	RateConnect       = "smb_connect"
)

// maxConnectPayload admits the largest password and the other fields.
const maxConnectPayload = 24 << 10

var errRequestID = fault.New(fault.InvalidRequest, "Valid request ID required")

// Routes are the smb.* message types. Their results are the success
// payloads of the Python release; the shim produces the events of today
// from them. With SMB_ENABLED false the area mounts none of them.
func (s *Service) Routes() []protocol.Route {
	mutation := protocol.Spec{Mutates: true, RateKey: RateShareMutation}
	connect := protocol.Spec{Async: true, Mutates: true, RateKey: RateConnect, MaxPayload: maxConnectPayload,
		Timeout: s.Config.ConnectTimeout + 2*s.Config.IOIdleTimeout + 5*time.Second}
	return []protocol.Route{
		protocol.Handle(protocol.TypeSMBShareList, protocol.Spec{RateKey: RateShareList}, s.handleList),
		protocol.Handle(protocol.TypeSMBShareSave, mutation, s.handleSave),
		protocol.Handle(protocol.TypeSMBShareDelete, mutation, s.handleDelete),
		protocol.Handle(protocol.TypeSMBConnect, connect, s.handleConnect),
		protocol.Handle(protocol.TypeSMBConnectCancel, protocol.Spec{}, s.handleCancel),
	}
}

func (s *Service) handleList(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (protocol.SMBShares, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.SMBShares{}, err
	}
	recs, err := s.Shares.List(ctx, p.UserID)
	return protocol.SMBShares{SMBShares: recs}, err
}

func (s *Service) handleSave(ctx context.Context, _ protocol.Peer, req protocol.SMBShareSave) (protocol.SMBShareSaved, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.SMBShareSaved{}, err
	}
	if requestID(req.RequestID) == "" {
		return protocol.SMBShareSaved{}, errRequestID
	}
	rec, err := s.Shares.Save(ctx, p.UserID, SaveRequest{ID: req.ID, Name: req.Name, Host: req.Host, Share: req.Share,
		Domain: req.Domain, Username: req.Username})
	if err == nil {
		s.logger().InfoContext(ctx, "SMB share definition saved", "user_id", p.UserID, "share_id", recordID(rec))
	}
	return protocol.SMBShareSaved{Share: rec}, err
}

func (s *Service) handleDelete(ctx context.Context, _ protocol.Peer, req protocol.SMBShareDelete) (protocol.SMBShareDeleted, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.SMBShareDeleted{}, err
	}
	if requestID(req.RequestID) == "" {
		return protocol.SMBShareDeleted{}, errRequestID
	}
	id, ok := jsonString(req.ShareID)
	if !ok || id == "" {
		return protocol.SMBShareDeleted{}, fault.New(fault.ValidationError, "SMB share ID required")
	}
	if err := s.Shares.Delete(ctx, p.UserID, id); err != nil {
		return protocol.SMBShareDeleted{}, err
	}
	s.logger().InfoContext(ctx, "SMB share definition deleted", "user_id", p.UserID, "share_id", id)
	return protocol.SMBShareDeleted{ShareID: id}, nil
}

func (s *Service) handleCancel(ctx context.Context, peer protocol.Peer, req protocol.SMBConnectCancel) (protocol.Empty, error) {
	if id := requestID(req.RequestID); id != "" {
		s.Cancel(peer.Principal().UserID, peer.ID(), id)
	}
	return protocol.Empty{}, nil
}

func (s *Service) handleConnect(ctx context.Context, peer protocol.Peer, req protocol.SMBConnect) (protocol.SMBConnected, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.SMBConnected{}, err
	}
	id := requestID(req.RequestID)
	if id == "" {
		return protocol.SMBConnected{}, errRequestID
	}
	cr, err := connectRequest(id, req)
	if err != nil {
		return protocol.SMBConnected{}, err
	}
	defer clear(cr.Target.Password)
	live := func() bool { return peer.Context().Err() == nil }
	d, caps, err := s.Connect(ctx, p, peer.ID(), cr, live)
	if err != nil {
		return protocol.SMBConnected{}, s.connectFailure(ctx, p, cr.Target.Host, cr.Target.Share, err)
	}
	s.logger().InfoContext(ctx, "SMB source connected", "user_id", p.UserID, "host", cr.Target.Host, "share", cr.Target.Share)
	return protocol.SMBConnected{FileSource: files.PublicSource(d, caps)}, nil
}

// connectRequest applies the input checks of handle_smb_quick_connect: a
// password, or a saved password instead of one, never both.
func connectRequest(id string, req protocol.SMBConnect) (ConnectRequest, error) {
	invalid := fault.New(fault.InvalidRequest, "")
	str := func(v []byte, optional bool) (string, bool) {
		if optional && len(v) == 0 {
			return "", true
		}
		return jsonString(v)
	}
	host, ok1 := str(req.Host, false)
	share, ok2 := str(req.Share, false)
	user, ok3 := str(req.Username, false)
	domain, ok4 := str(req.Domain, true)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return ConnectRequest{}, invalid
	}
	cr := ConnectRequest{RequestID: id, Target: Target{Host: host, Share: share, Domain: domain, Username: user}}
	if len(req.CredentialID) > 0 && req.CredentialID.Kind() != 'n' {
		ref, ok := jsonString(req.CredentialID)
		if pw, _ := str(req.Password, true); !ok || ref == "" || pw != "" {
			return ConnectRequest{}, invalid
		}
		token, _ := str(req.CredentialTargetToken, true)
		cr.CredentialID, cr.TargetToken = ref, token
		return cr, nil
	}
	pw, ok := str(req.Password, false)
	if !ok {
		return ConnectRequest{}, invalid
	}
	cr.Target.Password = []byte(pw)
	return cr, nil
}

// ResourceTarget is the current target of the saved share id of owner,
// for the review rules of saved passwords (vault.Resources through
// cmd/webssh).
func (s *Service) ResourceTarget(ctx context.Context, owner int64, id string) (ShareFields, error) {
	return s.Shares.Lookup(ctx, owner, id)
}

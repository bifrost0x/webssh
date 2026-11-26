package vault

import (
	"context"

	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// Rate-limit buckets (SSH_KEY_LIST_RATELIMIT, SSH_KEY_WRITE_RATELIMIT).
// Unlike the Python release, changes do not spend the list budget
// (design weakness W-010): managing keys no longer locks the list.
const (
	RateKeyList  = "ssh_key_list"
	RateKeyWrite = "ssh_key_write"
)

// Routes returns the realtime routes of keys.*.
func (s *Service) Routes() []protocol.Route {
	write := protocol.Spec{Mutates: true, RateKey: RateKeyWrite}
	material := protocol.Spec{Mutates: true, RateKey: RateKeyWrite, MaxPayload: protocol.MaxKeyPayload, Async: true}
	return []protocol.Route{
		protocol.Handle(protocol.TypeKeysList, protocol.Spec{RateKey: RateKeyList}, s.listRoute),
		protocol.Handle(protocol.TypeKeysUpload, material, s.uploadRoute),
		protocol.Handle(protocol.TypeKeysRename, write, s.renameRoute),
		protocol.Handle(protocol.TypeKeysReplace, material, s.replaceRoute),
		protocol.Handle(protocol.TypeKeysDelete, write, s.deleteRoute),
	}
}

func (s *Service) listRoute(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (*protocol.KeysList, error) {
	keys, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	out := &protocol.KeysList{Keys: make([]protocol.KeySummary, 0, len(keys))}
	for _, k := range keys {
		out.Keys = append(out.Keys, wire(k))
	}
	return out, nil
}

func (s *Service) uploadRoute(ctx context.Context, _ protocol.Peer, rq protocol.KeysUpload) (*protocol.KeyResult, error) {
	return result(s.Upload(ctx, Upload{Name: rq.Name, Content: rq.KeyContent, Passphrase: rq.Passphrase, Grant: rq.StepUp}))
}

func (s *Service) renameRoute(ctx context.Context, _ protocol.Peer, rq protocol.KeysRename) (*protocol.KeyResult, error) {
	return result(s.Rename(ctx, rq.KeyID, rq.Name))
}

func (s *Service) replaceRoute(ctx context.Context, _ protocol.Peer, rq protocol.KeysReplace) (*protocol.KeyResult, error) {
	return result(s.Replace(ctx, Replace{ID: rq.KeyID, Content: rq.KeyContent, Passphrase: rq.Passphrase, Grant: rq.StepUp}))
}

func (s *Service) deleteRoute(ctx context.Context, _ protocol.Peer, rq protocol.KeysDelete) (*protocol.Empty, error) {
	if err := s.Delete(ctx, rq.KeyID, rq.StepUp); err != nil {
		return nil, err
	}
	return &protocol.Empty{}, nil
}

func result(k Summary, err error) (*protocol.KeyResult, error) {
	if err != nil {
		return nil, err
	}
	return &protocol.KeyResult{Key: wire(k)}, nil
}

func wire(k Summary) protocol.KeySummary {
	return protocol.KeySummary{
		ID: k.ID, Name: k.Name, Filename: k.ID + ".pem", KeyType: k.KeyType,
		Encrypted: true, UploadedAt: k.UploadedAt, Usable: k.Usable,
	}
}

package hosts

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// connectionMutation is the rate-limit bucket of every change to saved
// connection data (RATELIMIT_CONNECTION_MUTATION); lists stay outside it,
// as in Python, so a throttled list cannot make routes look missing.
const connectionMutation = "connection_mutation"

// maxProfilePayload admits a profile with the largest startup commands and
// command parameters the store accepts.
const maxProfilePayload = 160 << 10

// Routes are the hosts.* message types of schema v1. Their results are the
// success payloads of the Python release without "success"; the shim
// produces the push events of today from them.
func (s *Service) Routes() []protocol.Route {
	mutation := protocol.Spec{Mutates: true, RateKey: connectionMutation}
	profileSave := mutation
	profileSave.MaxPayload = maxProfilePayload
	return []protocol.Route{
		protocol.Handle(protocol.TypeHostsProfileList, protocol.Spec{}, s.handleProfileList),
		protocol.Handle(protocol.TypeHostsProfileSave, profileSave, s.handleProfileSave),
		protocol.Handle(protocol.TypeHostsProfileDelete, mutation, s.handleProfileDelete),
		protocol.Handle(protocol.TypeHostsProfileOrganize, mutation, s.handleProfileOrganize),
		protocol.Handle(protocol.TypeHostsProfileMove, mutation, s.handleProfileMove),
		protocol.Handle(protocol.TypeHostsJumpList, protocol.Spec{}, s.handleJumpList),
		protocol.Handle(protocol.TypeHostsJumpSave, mutation, s.handleJumpSave),
		protocol.Handle(protocol.TypeHostsJumpDelete, mutation, s.handleJumpDelete),
		protocol.Handle(protocol.TypeHostsSOCKSList, protocol.Spec{}, s.handleSOCKSList),
		protocol.Handle(protocol.TypeHostsSOCKSSave, mutation, s.handleSOCKSSave),
		protocol.Handle(protocol.TypeHostsSOCKSDelete, mutation, s.handleSOCKSDelete),
	}
}

func (s *Service) handleProfileList(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (protocol.HostsProfiles, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsProfiles{}, err
	}
	profiles, err := s.Profiles(ctx, p.UserID)
	return protocol.HostsProfiles{Profiles: profiles}, err
}

func (s *Service) handleProfileSave(ctx context.Context, _ protocol.Peer, req protocol.HostsProfileSave) (protocol.HostsProfile, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsProfile{}, err
	}
	profile, err := s.SaveProfile(ctx, p.UserID, req)
	return protocol.HostsProfile{Profile: profile}, err
}

func (s *Service) handleProfileDelete(ctx context.Context, _ protocol.Peer, req protocol.HostsProfileRef) (protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.Empty{}, err
	}
	return protocol.Empty{}, s.DeleteProfile(ctx, p.UserID, req.ProfileID)
}

func (s *Service) handleProfileOrganize(ctx context.Context, _ protocol.Peer, req protocol.HostsProfileOrganize) (protocol.HostsProfile, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsProfile{}, err
	}
	profile, err := s.OrganizeProfile(ctx, p.UserID, req)
	return protocol.HostsProfile{Profile: profile}, err
}

func (s *Service) handleProfileMove(ctx context.Context, _ protocol.Peer, req protocol.HostsProfileMove) (protocol.HostsMoved, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsMoved{}, err
	}
	return s.MoveProfile(ctx, p.UserID, req)
}

func (s *Service) handleJumpList(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (protocol.HostsJumpHosts, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsJumpHosts{}, err
	}
	jumps, err := s.JumpHosts(ctx, p.UserID)
	return protocol.HostsJumpHosts{JumpHosts: jumps}, err
}

func (s *Service) handleJumpSave(ctx context.Context, _ protocol.Peer, req protocol.HostsJumpSave) (protocol.HostsJumpHost, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsJumpHost{}, err
	}
	jump, err := s.SaveJumpHost(ctx, p.UserID, req)
	return protocol.HostsJumpHost{JumpHost: jump}, err
}

func (s *Service) handleJumpDelete(ctx context.Context, _ protocol.Peer, req protocol.HostsJumpRef) (protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.Empty{}, err
	}
	return protocol.Empty{}, s.DeleteJumpHost(ctx, p.UserID, req.JumpHostID)
}

func (s *Service) handleSOCKSList(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (protocol.HostsSOCKSProxies, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsSOCKSProxies{}, err
	}
	proxies, err := s.SOCKSProxies(ctx, p.UserID)
	return protocol.HostsSOCKSProxies{SOCKSProxies: proxies}, err
}

func (s *Service) handleSOCKSSave(ctx context.Context, _ protocol.Peer, req protocol.HostsSOCKSSave) (protocol.HostsSOCKSProxy, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.HostsSOCKSProxy{}, err
	}
	proxy, err := s.SaveSOCKSProxy(ctx, p.UserID, req)
	return protocol.HostsSOCKSProxy{SOCKSProxy: proxy}, err
}

func (s *Service) handleSOCKSDelete(ctx context.Context, _ protocol.Peer, req protocol.HostsSOCKSRef) (protocol.Empty, error) {
	p, err := principal.Require(ctx)
	if err != nil {
		return protocol.Empty{}, err
	}
	return protocol.Empty{}, s.DeleteSOCKSProxy(ctx, p.UserID, req.SOCKSProxyID)
}

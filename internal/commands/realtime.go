package commands

import (
	"context"

	"github.com/bifrost0x/webssh/internal/principal"
	"github.com/bifrost0x/webssh/internal/realtime/protocol"
)

// RateMutation is the rate bucket of every change to commands and sets
// (COMMAND_MUTATION_RATELIMIT, 60 per minute by default).
const RateMutation = "command_mutation"

// RateMutationMessage is the refusal of the rate limit, the text of
// _COMMAND_MUTATION_RATE_ERROR in app/socket_events.py.
const RateMutationMessage = "Too many command changes. Please wait before trying again."

// Routes are the message types of the area "commands".
func (l *Library) Routes() []protocol.Route {
	read := protocol.Spec{}
	write := protocol.Spec{Mutates: true, RateKey: RateMutation, RateMessage: RateMutationMessage, MaxPayload: protocol.CommandMaxPayload}
	return []protocol.Route{
		protocol.Handle(protocol.TypeCommandsList, read, l.handleList),
		protocol.Handle(protocol.TypeCommandsAdd, write, l.handleAdd),
		protocol.Handle(protocol.TypeCommandsUpdate, write, l.handleUpdate),
		protocol.Handle(protocol.TypeCommandsDelete, write, l.handleDelete),
		protocol.Handle(protocol.TypeCommandSetList, read, l.handleSets),
		protocol.Handle(protocol.TypeCommandSetResolve, protocol.Spec{MaxPayload: 64 << 10}, l.handleResolve),
		protocol.Handle(protocol.TypeCommandSetSave, write, l.handleSave),
		protocol.Handle(protocol.TypeCommandSetDuplicate, write, l.handleDuplicate),
		protocol.Handle(protocol.TypeCommandSetDelete, write, l.handleDeleteSet),
		protocol.Handle(protocol.TypeCommandSetConvert, write, l.handleConvert),
	}
}

func owner(ctx context.Context) (int64, error) {
	p, err := principal.Require(ctx)
	return p.UserID, err
}

func (l *Library) handleList(ctx context.Context, _ protocol.Peer, req protocol.CommandsList) (protocol.Commands, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.Commands{}, err
	}
	list, err := l.List(ctx, id, req.OSFilter)
	return protocol.Commands{Commands: list}, err
}

func (l *Library) handleAdd(ctx context.Context, _ protocol.Peer, req protocol.CommandSave) (protocol.CommandSaved, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSaved{}, err
	}
	rec, err := l.Add(ctx, id, req)
	return protocol.CommandSaved{Command: rec}, err
}

func (l *Library) handleUpdate(ctx context.Context, _ protocol.Peer, req protocol.CommandSave) (protocol.CommandSaved, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSaved{}, err
	}
	rec, err := l.Update(ctx, id, req)
	return protocol.CommandSaved{Command: rec}, err
}

func (l *Library) handleDelete(ctx context.Context, _ protocol.Peer, req protocol.CommandDelete) (protocol.CommandDeleted, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandDeleted{}, err
	}
	deleted, err := l.Delete(ctx, id, req.CommandID)
	return protocol.CommandDeleted{CommandID: deleted}, err
}

func (l *Library) handleSets(ctx context.Context, _ protocol.Peer, _ protocol.Empty) (protocol.CommandSets, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSets{}, err
	}
	sets, err := l.Sets(ctx, id)
	return protocol.CommandSets{CommandSets: sets}, err
}

func (l *Library) handleResolve(ctx context.Context, _ protocol.Peer, req protocol.CommandSetResolve) (protocol.CommandSetResolved, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSetResolved{}, err
	}
	text, err := l.ResolveParameters(ctx, id, req.CommandSetID, req.Values, req.UseSudo)
	return protocol.CommandSetResolved{ResolvedCommand: text}, err
}

func (l *Library) handleSave(ctx context.Context, _ protocol.Peer, req protocol.CommandSetSave) (protocol.CommandSetSaved, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSetSaved{}, err
	}
	set, err := l.SaveSet(ctx, id, req)
	return protocol.CommandSetSaved{CommandSet: set}, err
}

func (l *Library) handleDuplicate(ctx context.Context, _ protocol.Peer, req protocol.CommandSetRef) (protocol.CommandSetSaved, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSetSaved{}, err
	}
	set, err := l.DuplicateSet(ctx, id, req.CommandSetID)
	return protocol.CommandSetSaved{CommandSet: set}, err
}

func (l *Library) handleDeleteSet(ctx context.Context, _ protocol.Peer, req protocol.CommandSetRef) (protocol.CommandSetDeleted, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSetDeleted{}, err
	}
	deleted, err := l.DeleteSet(ctx, id, req.CommandSetID)
	return protocol.CommandSetDeleted{CommandSetID: deleted}, err
}

func (l *Library) handleConvert(ctx context.Context, _ protocol.Peer, req protocol.CommandSetConvert) (protocol.CommandSetConverted, error) {
	id, err := owner(ctx)
	if err != nil {
		return protocol.CommandSetConverted{}, err
	}
	set, profile, err := l.Convert(ctx, id, req)
	return protocol.CommandSetConverted{CommandSet: set, Profile: profile}, err
}

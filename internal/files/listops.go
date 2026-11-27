package files

import (
	"context"
	"errors"

	"github.com/bifrost0x/webssh/internal/fault"
)

// Page is one page of a directory listing. Next is the cursor of the
// following page, empty on the last one.
type Page struct {
	Entries []Entry
	Next    string
}

// List reads a page of the directory dir (list_directory). An empty
// cursor opens a new snapshot of the directory, any other continues one;
// "" and "." name the home directory. requestID lets the caller cancel
// the first page while it is still being read.
func (s *Service) List(ctx context.Context, c Caller, sourceID, requestID, dir, cursor string) (Page, error) {
	r, err := s.resolve(ctx, c, sourceID, CapList)
	if err != nil {
		return Page{}, err
	}
	defer r.release()
	if cursor != "" {
		return s.continueListing(ctx, c, sourceID, dir, cursor)
	}
	p, err := s.listPath(ctx, r, dir)
	if err != nil {
		return Page{}, err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	sn, err := s.list.reserve(c.owner(), sourceID, dir, requestID, cancel)
	if err != nil {
		return Page{}, err
	}
	// reserve returned with sn.read held: nobody closes sn before its
	// listing is known.
	listing, err := r.b.OpenListing(ctx, p)
	var entries []Entry
	var more bool
	if err == nil {
		sn.listing = listing
		entries, more, err = s.readPage(ctx, listing, 0)
	}
	sn.read.Unlock()
	if err == nil && ctx.Err() != nil {
		err = errListGone
	}
	if err != nil || !more {
		s.list.retire(sn)
		if errors.Is(ctx.Err(), context.Canceled) && err != nil {
			err = errListGone
		}
		return Page{Entries: entries}, err
	}
	next, ok := s.list.opened(sn, len(entries))
	if !ok {
		s.list.retire(sn)
		return Page{}, errListGone
	}
	return Page{Entries: entries, Next: next}, nil
}

func (s *Service) listPath(ctx context.Context, r resolved, dir string) (string, error) {
	if dir == "" || dir == "." {
		return r.b.Home(ctx)
	}
	return s.clean(dir)
}

// readPage reads one page; offset is the number of entries already read,
// for the member limit.
func (s *Service) readPage(ctx context.Context, l Listing, offset int) ([]Entry, bool, error) {
	entries, more, err := l.Next(ctx, s.opts.PageSize)
	switch {
	case err != nil:
		return nil, false, err
	case len(entries) > s.opts.PageSize || more && len(entries) == 0:
		return nil, false, invalidListing
	case offset+len(entries) > s.opts.MaxMembers:
		return nil, false, errMembers
	}
	return entries, more, nil
}

var invalidListing = fault.New(fault.OperationFailed, "The server sent an invalid directory listing.")

func (s *Service) continueListing(ctx context.Context, c Caller, sourceID, dir, cursor string) (Page, error) {
	sn, offset, err := s.list.find(cursor, c.owner(), sourceID, dir)
	if err != nil {
		return Page{}, err
	}
	sn.read.Lock()
	// A second continuation with the same cursor waits here and then
	// finds the offset moved on.
	if sn.listing == nil || !s.list.at(sn, offset) {
		sn.read.Unlock()
		return Page{}, errCursor
	}
	entries, more, err := s.readPage(ctx, sn.listing, offset)
	sn.read.Unlock()
	if err != nil || !more {
		s.list.retire(sn)
		return Page{Entries: entries}, err
	}
	next, ok := s.list.advance(sn, offset, len(entries))
	if !ok {
		return Page{}, errCursor
	}
	return Page{Entries: entries, Next: next}, nil
}

// CancelListing closes a listing by its continuation cursor or by the
// request id of its first page. It never says whether one existed.
func (s *Service) CancelListing(c Caller, sourceID, cursor, listingRequestID string) {
	if cursor != "" {
		s.list.cancelCursor(cursor, c.owner(), sourceID)
	}
	if listingRequestID != "" {
		s.list.cancelRequest(listingRequestID, c.owner(), sourceID)
	}
}

// Home returns the start directory of a source (get_home_directory).
func (s *Service) Home(ctx context.Context, c Caller, sourceID string) (string, error) {
	r, err := s.resolve(ctx, c, sourceID, CapList)
	if err != nil {
		return "", err
	}
	defer r.release()
	return r.b.Home(ctx)
}

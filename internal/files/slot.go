package files

import (
	"context"
	"sync"

	"github.com/bifrost0x/webssh/internal/principal"
)

// Slot is the quota of one source that is not open yet (Reserve).
type Slot struct {
	r       *Registry
	p       principal.Principal
	kind    SourceKind
	once    sync.Once
	release func()
}

// Reserve takes the quota of a new source of kind for p before it is
// opened, as the Python release reserved before it connected. The slot
// passes to the source with Slot.Add; Release frees an unused slot.
func (r *Registry) Reserve(ctx context.Context, p principal.Principal, kind SourceKind) (*Slot, error) {
	release := func() {}
	if kind != SourceSFTPSession && r.opts.Quotas != nil {
		var err error
		if release, err = r.opts.Quotas.Reserve(ctx, quickConnection, p.UserID, 1); err != nil {
			return nil, err
		}
	}
	return &Slot{r: r, p: p, kind: kind, release: release}, nil
}

// Add registers b on the slot and returns the new source id; the source
// owns the quota from then on. Add takes ownership of b: on failure b is
// closed and the slot freed. A slot is used once.
func (s *Slot) Add(d Descriptor, b Backend) (string, error) {
	id, err := FormatSourceID(s.kind, newHandle())
	if err != nil {
		s.Release()
		_ = b.Close()
		return "", err
	}
	return id, s.add(id, d, b)
}

// add inserts b under id with the slot's quota.
func (s *Slot) add(id string, d Descriptor, b Backend) error {
	first := false
	s.once.Do(func() { first = true })
	if !first {
		_ = b.Close()
		return errUnavailable
	}
	d.SourceID = id
	if err := s.r.insert(s.p, s.kind, d, b, s.release); err != nil {
		s.release()
		_ = b.Close()
		return err
	}
	return nil
}

// Release frees the slot unless Add used it.
func (s *Slot) Release() { s.once.Do(s.release) }

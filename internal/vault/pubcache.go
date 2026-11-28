package vault

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// maxPublicKeys bounds the cache; past it the cache starts over.
const maxPublicKeys = 4096

// publicKeys remembers the public key of a sealed key, by owner, key ID
// and the sealed value itself: a replaced key or a resealed one is a new
// entry, so nothing needs invalidating.
type publicKeys struct {
	mu sync.Mutex
	m  map[[sha256.Size]byte][]byte
}

func publicKeyID(owner int64, keyID string, sealed []byte) [sha256.Size]byte {
	h := sha256.New()
	_ = binary.Write(h, binary.BigEndian, owner)
	_ = binary.Write(h, binary.BigEndian, uint64(len(keyID)))
	h.Write([]byte(keyID))
	h.Write(sealed)
	var id [sha256.Size]byte
	h.Sum(id[:0])
	return id
}

func (c *publicKeys) get(id [sha256.Size]byte) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pub, ok := c.m[id]
	return pub, ok
}

func (c *publicKeys) put(id [sha256.Size]byte, pub []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil || len(c.m) >= maxPublicKeys {
		c.m = map[[sha256.Size]byte][]byte{}
	}
	c.m[id] = pub
}

// PublicKey returns the SSH wire form of the public key of the owner's
// usable key. Automation binds every reviewed run to it and checks it many
// times per run; opening the sealed key costs an AEAD open and a private
// key parse, a full private-key operation for RSA. The row is read every
// time, the sealed value is opened only the first time it is seen.
func (s *Service) PublicKey(ctx context.Context, owner int64, keyID string) ([]byte, error) {
	r, err := s.usableRow(ctx, owner, keyID)
	if err != nil {
		return nil, err
	}
	id := publicKeyID(owner, keyID, r.Sealed)
	if pub, ok := s.pub.get(id); ok {
		return append([]byte(nil), pub...), nil
	}
	signer, err := s.openKey(owner, keyID, r)
	if err != nil {
		return nil, err
	}
	pub := signer.PublicKey().Marshal()
	s.pub.put(id, pub)
	return append([]byte(nil), pub...), nil
}

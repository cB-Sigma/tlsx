// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// newGCMForTLS12 and newGCMForTLS13 replace crypto/internal/fips140's
// nonce-enforcing GCM constructors with crypto/cipher's GCM. The TLS 1.2
// one always applies a check that upstream's
// crypto/internal/fips140/aes/gcm applies in FIPS 140 mode: every sealed
// record's explicit nonce (the record sequence number) must be larger than
// the last one. This is our own code, not a copy of Go's.

func newGCMForTLS12(b cipher.Block) (cipher.AEAD, error) {
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &gcmTLS12{AEAD: g}, nil
}

func newGCMForTLS13(b cipher.Block) (cipher.AEAD, error) { return cipher.NewGCM(b) }

type gcmTLS12 struct {
	cipher.AEAD
	next  uint64
	first bool
}

func (g *gcmTLS12) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 12 {
		panic("tlsx: GCM nonce is not 12 bytes")
	}
	counter := binary.BigEndian.Uint64(nonce[4:])
	if g.first && counter < g.next {
		panic(errors.New("tlsx: TLS 1.2 GCM nonce reused or out of order"))
	}
	g.first = true
	if counter == ^uint64(0) {
		panic("tlsx: TLS 1.2 GCM nonce counter exhausted")
	}
	g.next = counter + 1
	return g.AEAD.Seal(dst, nonce, plaintext, additionalData)
}

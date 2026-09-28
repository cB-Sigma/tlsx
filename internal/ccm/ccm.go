// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package ccm implements the CCM mode of a 128-bit block cipher (RFC 3610,
// NIST SP 800-38C) as a crypto/cipher AEAD, for tlsx's CCM cipher suites
// (TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256, RFC 8446 B.4; the
// TLS 1.2 PSK CCM suites of RFC 6655). The CCM construction is our own
// code; sliceForAppend (slice.go) is Go's.
package ccm

import (
	"crypto/cipher"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// ErrOpen is returned when a ciphertext does not authenticate.
var ErrOpen = errors.New("ccm: message authentication failed")

type ccm struct {
	b        cipher.Block
	nonceLen int
	tagLen   int
}

// New returns CCM over b (a 16-byte block cipher) with nonces of nonceSize
// bytes (7 to 13) and tags of tagSize bytes (4, 6, 8, 10, 12, 14 or 16).
func New(b cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if b.BlockSize() != 16 {
		return nil, errors.New("ccm: block size is not 16 bytes")
	}
	if nonceSize < 7 || nonceSize > 13 {
		return nil, errors.New("ccm: nonce size outside 7 to 13 bytes")
	}
	if tagSize < 4 || tagSize > 16 || tagSize%2 != 0 {
		return nil, errors.New("ccm: tag size not an even number from 4 to 16")
	}
	return &ccm{b: b, nonceLen: nonceSize, tagLen: tagSize}, nil
}

func (c *ccm) NonceSize() int { return c.nonceLen }
func (c *ccm) Overhead() int  { return c.tagLen }

// maxPayload is the longest payload the length field (15-nonceSize bytes)
// can carry.
func (c *ccm) maxPayload() uint64 {
	q := 15 - c.nonceLen
	if q >= 8 {
		return ^uint64(0)
	}
	return 1<<(8*uint(q)) - 1
}

// counter writes counter block i: flags q-1, the nonce, i big-endian.
func (c *ccm) counter(dst *[16]byte, nonce []byte, i uint64) {
	*dst = [16]byte{}
	dst[0] = byte(15 - c.nonceLen - 1)
	copy(dst[1:], nonce)
	for j := 15; j > c.nonceLen; j-- {
		dst[j] = byte(i)
		i >>= 8
	}
}

// ctr XORs in with the key stream starting at counter 1.
func (c *ccm) ctr(out, in, nonce []byte) {
	var ctrBlk, ks [16]byte
	for i := 0; i < len(in); i += 16 {
		c.counter(&ctrBlk, nonce, uint64(i/16+1))
		c.b.Encrypt(ks[:], ctrBlk[:])
		end := min(i+16, len(in))
		subtle.XORBytes(out[i:end], in[i:end], ks[:end-i])
	}
}

// tag computes the CBC-MAC over B0, the encoded additional data and the
// plaintext, encrypted with counter block 0.
func (c *ccm) tag(nonce, plaintext, ad []byte) []byte {
	var b0 [16]byte
	b0[0] = byte((c.tagLen-2)/2)<<3 | byte(15-c.nonceLen-1)
	if len(ad) > 0 {
		b0[0] |= 0x40
	}
	copy(b0[1:], nonce)
	l := uint64(len(plaintext))
	for j := 15; j > c.nonceLen; j-- {
		b0[j] = byte(l)
		l >>= 8
	}
	var mac [16]byte
	c.b.Encrypt(mac[:], b0[:])
	var blk [16]byte
	n := 0 // bytes in blk
	absorb := func(p []byte) {
		for len(p) > 0 {
			k := copy(blk[n:], p)
			n += k
			p = p[k:]
			if n == 16 {
				subtle.XORBytes(mac[:], mac[:], blk[:])
				c.b.Encrypt(mac[:], mac[:])
				blk, n = [16]byte{}, 0
			}
		}
	}
	flush := func() {
		if n > 0 {
			subtle.XORBytes(mac[:], mac[:], blk[:])
			c.b.Encrypt(mac[:], mac[:])
			blk, n = [16]byte{}, 0
		}
	}
	if len(ad) > 0 {
		switch {
		case uint64(len(ad)) < 0xFF00:
			absorb(binary.BigEndian.AppendUint16(nil, uint16(len(ad))))
		case uint64(len(ad)) <= 0xFFFFFFFF:
			absorb(binary.BigEndian.AppendUint32([]byte{0xFF, 0xFE}, uint32(len(ad))))
		default:
			absorb(binary.BigEndian.AppendUint64([]byte{0xFF, 0xFF}, uint64(len(ad))))
		}
		absorb(ad)
		flush()
	}
	absorb(plaintext)
	flush()
	var s0, ctr0 [16]byte
	c.counter(&ctr0, nonce, 0)
	c.b.Encrypt(s0[:], ctr0[:])
	t := make([]byte, c.tagLen)
	subtle.XORBytes(t, mac[:c.tagLen], s0[:c.tagLen])
	return t
}

func (c *ccm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.nonceLen {
		panic("ccm: incorrect nonce length")
	}
	if uint64(len(plaintext)) > c.maxPayload() {
		panic("ccm: plaintext too long for the nonce size")
	}
	t := c.tag(nonce, plaintext, additionalData)
	ret, out := sliceForAppend(dst, len(plaintext)+c.tagLen)
	c.ctr(out[:len(plaintext)], plaintext, nonce)
	copy(out[len(plaintext):], t)
	return ret
}

func (c *ccm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.nonceLen {
		panic("ccm: incorrect nonce length")
	}
	if len(ciphertext) < c.tagLen || uint64(len(ciphertext)-c.tagLen) > c.maxPayload() {
		return nil, ErrOpen
	}
	body, tag := ciphertext[:len(ciphertext)-c.tagLen], ciphertext[len(ciphertext)-c.tagLen:]
	ret, out := sliceForAppend(dst, len(body))
	c.ctr(out, body, nonce)
	if subtle.ConstantTimeCompare(c.tag(nonce, out, additionalData), tag) != 1 {
		clear(out)
		return nil, ErrOpen
	}
	return ret, nil
}

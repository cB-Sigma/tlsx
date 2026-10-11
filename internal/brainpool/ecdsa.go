// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package brainpool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/cB-Sigma/tlsx/internal/bigmod"
)

// ---------------------------------------------------------------------------
// ECDH

// randomScalar draws a uniform scalar in [1, n-1] by rejection sampling.
func (c *curve) randomScalar(rand io.Reader) ([]byte, *bigmod.Nat, error) {
	if rand == nil {
		rand = crand.Reader
	}
	excess := c.size*8 - c.n.BitLen()
	b := make([]byte, c.size)
	for range 1000 {
		if _, err := io.ReadFull(rand, b); err != nil {
			return nil, nil, err
		}
		b[0] &= byte(0xff >> uint(excess))
		if s, err := c.scalarFromBytes(b); err == nil {
			return b, s, nil
		}
	}
	return nil, nil, errors.New("brainpool: random source keeps producing out-of-range scalars")
}

// GenerateECDHKey returns a new private scalar (c.size bytes, big-endian) and
// its public point in uncompressed form (0x04 || X || Y).
func GenerateECDHKey(c elliptic.Curve, rand io.Reader) (priv []byte, pub []byte, err error) {
	cv, err := toCurve(c)
	if err != nil {
		return nil, nil, err
	}
	d, _, err := cv.randomScalar(rand)
	if err != nil {
		return nil, nil, err
	}
	pub, err = cv.marshalPoint(cv.scalarBaseMult(d))
	if err != nil {
		return nil, nil, err
	}
	return d, pub, nil
}

// ECDH computes the shared secret for TLS: the x-coordinate of priv*peer,
// always c.size bytes. priv must be c.size bytes in [1, n-1]; peer must be an
// uncompressed point on the curve.
func ECDH(c elliptic.Curve, priv, peer []byte) ([]byte, error) {
	cv, err := toCurve(c)
	if err != nil {
		return nil, err
	}
	if _, err := cv.scalarFromBytes(priv); err != nil {
		return nil, err
	}
	q, err := cv.pointFromUncompressed(peer)
	if err != nil {
		return nil, err
	}
	r := cv.scalarMult(q, priv)
	if cv.isIdentity(r) == 1 {
		return nil, errors.New("brainpool: ECDH result is the point at infinity")
	}
	x, _ := cv.affine(r)
	return x, nil
}

// ---------------------------------------------------------------------------
// ECDSA keys

// PrivateKey is an ECDSA private key on a brainpool curve. It implements
// crypto.Signer.
type PrivateKey struct {
	c   *curve
	d   []byte // c.size bytes, in [1, n-1]
	pub *ecdsa.PublicKey
}

// GenerateKey returns a new random key on c.
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
	cv, err := toCurve(c)
	if err != nil {
		return nil, err
	}
	d, _, err := cv.randomScalar(rand)
	if err != nil {
		return nil, err
	}
	return newPrivateKey(cv, d)
}

// NewPrivateKey returns the key with scalar d (big-endian; shorter encodings
// are left-padded, longer ones may only carry leading zeros). d must be in
// [1, n-1].
func NewPrivateKey(c elliptic.Curve, d []byte) (*PrivateKey, error) {
	cv, err := toCurve(c)
	if err != nil {
		return nil, err
	}
	for len(d) > cv.size && d[0] == 0 {
		d = d[1:]
	}
	if len(d) > cv.size {
		return nil, errors.New("brainpool: private scalar too long")
	}
	buf := make([]byte, cv.size)
	copy(buf[cv.size-len(d):], d)
	return newPrivateKey(cv, buf)
}

func newPrivateKey(cv *curve, d []byte) (*PrivateKey, error) {
	if _, err := cv.scalarFromBytes(d); err != nil {
		return nil, err
	}
	q := cv.scalarBaseMult(d)
	if cv.isIdentity(q) == 1 {
		return nil, errors.New("brainpool: invalid private key")
	}
	x, y := cv.affine(q)
	return &PrivateKey{c: cv, d: d, pub: &ecdsa.PublicKey{
		Curve: cv, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y),
	}}, nil
}

// Public returns the public key as *ecdsa.PublicKey (Curve is the brainpool
// curve).
func (k *PrivateKey) Public() crypto.PublicKey {
	return &ecdsa.PublicKey{Curve: k.pub.Curve, X: new(big.Int).Set(k.pub.X), Y: new(big.Int).Set(k.pub.Y)}
}

// Curve returns the key's curve.
func (k *PrivateKey) Curve() elliptic.Curve { return k.c }

// Bytes returns the private scalar as c.size big-endian bytes.
func (k *PrivateKey) Bytes() []byte { return append([]byte(nil), k.d...) }

// ECDSA returns the same key as *ecdsa.PrivateKey. Note that ecdsa.Sign with
// it takes crypto/ecdsa's variable-time generic path; prefer k.Sign.
func (k *PrivateKey) ECDSA() *ecdsa.PrivateKey {
	pub := k.Public().(*ecdsa.PublicKey)
	return &ecdsa.PrivateKey{PublicKey: *pub, D: new(big.Int).SetBytes(k.d)}
}

// ---------------------------------------------------------------------------
// ECDSA signing and verification

func (c *curve) drbgHash() func() hash.Hash {
	switch {
	case c.size <= 32:
		return sha256.New
	case c.size <= 48:
		return sha512.New384
	default:
		return sha512.New
	}
}

// hashToScalar converts a digest to an integer mod n: keep the leftmost
// bitlen(n) bits, then reduce once (values are below 2^bitlen(n) < 2n).
func (c *curve) hashToScalar(digest []byte) *bigmod.Nat {
	bits := c.n.BitLen()
	nb := (bits + 7) / 8
	if len(digest) > nb {
		digest = digest[:nb]
	}
	buf := make([]byte, nb)
	copy(buf[nb-len(digest):], digest)
	if excess := len(digest)*8 - bits; excess > 0 {
		// Shift the whole buffer right by excess bits.
		v := new(big.Int).SetBytes(buf)
		v.Rsh(v, uint(excess))
		v.FillBytes(buf)
	}
	e, err := bigmod.NewNat().SetOverflowingBytes(buf, c.n)
	if err != nil {
		panic("brainpool: internal error reducing digest")
	}
	return e
}

// nonceSource is the HMAC-DRBG of RFC 6979 section 3.2, keyed with the private
// scalar, the reduced digest and extra random input (section 3.6).
type nonceSource struct {
	c    *curve
	h    func() hash.Hash
	k, v []byte
	used bool
}

func newNonceSource(c *curve, d, e, extra []byte) *nonceSource {
	h := c.drbgHash()
	hl := h().Size()
	ns := &nonceSource{c: c, h: h, k: make([]byte, hl), v: make([]byte, hl)}
	for i := range ns.v {
		ns.v[i] = 1
	}
	for _, sep := range []byte{0, 1} {
		m := hmac.New(h, ns.k)
		m.Write(ns.v)
		m.Write([]byte{sep})
		m.Write(d)
		m.Write(e)
		m.Write(extra)
		ns.k = m.Sum(nil)
		ns.v = ns.mac(ns.v)
	}
	return ns
}

func (ns *nonceSource) mac(parts ...[]byte) []byte {
	m := hmac.New(ns.h, ns.k)
	for _, p := range parts {
		m.Write(p)
	}
	return m.Sum(nil)
}

// next returns the next candidate nonce in [1, n-1].
func (ns *nonceSource) next() (*bigmod.Nat, []byte) {
	for {
		if ns.used {
			ns.k = ns.mac(ns.v, []byte{0})
			ns.v = ns.mac(ns.v)
		}
		ns.used = true
		var t []byte
		for len(t) < ns.c.size {
			ns.v = ns.mac(ns.v)
			t = append(t, ns.v...)
		}
		t = t[:ns.c.size]
		if excess := ns.c.size*8 - ns.c.n.BitLen(); excess > 0 {
			v := new(big.Int).SetBytes(t)
			v.Rsh(v, uint(excess))
			v.FillBytes(t)
		}
		if k, err := ns.c.scalarFromBytes(t); err == nil {
			return k, t
		}
	}
}

// Sign signs digest (a hash computed by the caller; it is truncated to the
// order's bit length as ECDSA specifies) and returns an ASN.1 DER
// Ecdsa-Sig-Value. opts is ignored: any hash (or none) is accepted.
func (k *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if rand == nil {
		rand = crand.Reader
	}
	c := k.c
	extra := make([]byte, 32)
	if _, err := io.ReadFull(rand, extra); err != nil {
		return nil, err
	}
	e := c.hashToScalar(digest)
	d, err := c.scalarFromBytes(k.d)
	if err != nil {
		return nil, err
	}
	ns := newNonceSource(c, k.d, e.Bytes(c.n), extra)
	for range 100 {
		kn, kb := ns.next()
		R := c.scalarBaseMult(kb)
		if c.isIdentity(R) == 1 {
			continue
		}
		xb, _ := c.affine(R)
		// x < p < 2n, so one conditional subtraction reduces it mod n.
		r, err := bigmod.NewNat().SetOverflowingBytes(xb, c.n)
		if err != nil {
			return nil, err
		}
		if r.IsZero() == 1 {
			continue
		}
		kInv := bigmod.NewNat().Exp(kn, c.nMinus2, c.n)
		s := bigmod.NewNat().Set(r)
		s.Mul(d, c.n) // r*d
		s.Add(e, c.n) // e + r*d
		s.Mul(kInv, c.n)
		if s.IsZero() == 1 {
			continue
		}
		return encodeSignature(r.Bytes(c.n), s.Bytes(c.n)), nil
	}
	return nil, errors.New("brainpool: failed to produce a signature")
}

// encodeSignature, addASN1IntBytes and parseSignature are adapted from Go's
// crypto/ecdsa/ecdsa.go: encodeSignature, addASN1IntBytes and parseSignature.
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
func encodeSignature(r, s []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		addASN1IntBytes(b, r)
		addASN1IntBytes(b, s)
	})
	return b.BytesOrPanic()
}

// addASN1IntBytes appends a non-negative big-endian integer as ASN.1 INTEGER.
func addASN1IntBytes(b *cryptobyte.Builder, v []byte) {
	for len(v) > 1 && v[0] == 0 {
		v = v[1:]
	}
	b.AddASN1(cbasn1.INTEGER, func(b *cryptobyte.Builder) {
		if len(v) == 0 || v[0]&0x80 != 0 {
			b.AddUint8(0)
		}
		b.AddBytes(v)
	})
}

func parseSignature(sig []byte) (r, s []byte, err error) {
	var inner cryptobyte.String
	var rb, sb big.Int
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) || !input.Empty() ||
		!inner.ReadASN1Integer(&rb) || !inner.ReadASN1Integer(&sb) || !inner.Empty() {
		return nil, nil, errors.New("brainpool: malformed signature")
	}
	if rb.Sign() <= 0 || sb.Sign() <= 0 {
		return nil, nil, errors.New("brainpool: signature value not positive")
	}
	return rb.Bytes(), sb.Bytes(), nil
}

// Verify reports whether sig (ASN.1 DER) is a valid ECDSA signature of digest
// by pub. It is variable time and handles only public data.
func Verify(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return false
	}
	c, err := toCurve(pub.Curve)
	if err != nil {
		return false
	}
	q, ok := c.bigToPoint(pub.X, pub.Y)
	if !ok || c.isIdentity(q) == 1 {
		return false
	}
	rb, sb, err := parseSignature(sig)
	if err != nil || len(rb) > c.size || len(sb) > c.size {
		return false
	}
	r, err := bigmod.NewNat().SetBytes(rb, c.n)
	if err != nil {
		return false
	}
	s, err := bigmod.NewNat().SetBytes(sb, c.n)
	if err != nil {
		return false
	}
	e := c.hashToScalar(digest)
	w := bigmod.NewNat().Exp(s, c.nMinus2, c.n)
	u1 := bigmod.NewNat().Set(e).Mul(w, c.n)
	u2 := bigmod.NewNat().Set(r).Mul(w, c.n)
	R := c.add(c.scalarBaseMult(u1.Bytes(c.n)), c.scalarMult(q, u2.Bytes(c.n)))
	if c.isIdentity(R) == 1 {
		return false
	}
	xb, _ := c.affine(R)
	v, err := bigmod.NewNat().SetOverflowingBytes(xb, c.n)
	if err != nil {
		return false
	}
	return v.Equal(r) == 1
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"io"
	"slices"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/bigmod"
	"github.com/cB-Abhinav-Gautam/tlsx/internal/brainpool"
)

// Key exchange groups tlsx adds: the finite field groups of RFC 7919 (TLS
// 1.3 key shares and the TLS 1.2 DHE suites) and the brainpool curves
// (TLS 1.2 ECDHE, RFC 7027; TLS 1.3, RFC 8734). Modular exponentiation
// uses the constant-time bigmod package (a copy of Go's
// crypto/internal/fips140/bigmod, pure Go); the brainpool arithmetic is
// constant time in the secret scalar (internal/brainpool).

// The RFC 7919 primes (Appendix A; generator 2). The tests check they are
// safe primes and that ffdhe2048 matches the formula of A.1.
const (
	ffdhe2048P = "" +
		"ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
		"a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
		"d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
		"984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
		"bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
		"ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
		"9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
		"c58ef1837d1683b2c6f34a26c1b2effa886b423861285c97ffffffffffffffff"
	ffdhe3072P = "" +
		"ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
		"a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
		"d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
		"984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
		"bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
		"ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
		"9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
		"c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b" +
		"bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c" +
		"aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff" +
		"5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e" +
		"0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b66c62e37ffffffffffffffff"
	ffdhe4096P = "" +
		"ffffffffffffffffadf85458a2bb4a9aafdc5620273d3cf1d8b9c583ce2d3695" +
		"a9e13641146433fbcc939dce249b3ef97d2fe363630c75d8f681b202aec4617a" +
		"d3df1ed5d5fd65612433f51f5f066ed0856365553ded1af3b557135e7f57c935" +
		"984f0c70e0e68b77e2a689daf3efe8721df158a136ade73530acca4f483a797a" +
		"bc0ab182b324fb61d108a94bb2c8e3fbb96adab760d7f4681d4f42a3de394df4" +
		"ae56ede76372bb190b07a7c8ee0a6d709e02fce1cdf7e2ecc03404cd28342f61" +
		"9172fe9ce98583ff8e4f1232eef28183c3fe3b1b4c6fad733bb5fcbc2ec22005" +
		"c58ef1837d1683b2c6f34a26c1b2effa886b4238611fcfdcde355b3b6519035b" +
		"bc34f4def99c023861b46fc9d6e6c9077ad91d2691f7f7ee598cb0fac186d91c" +
		"aefe130985139270b4130c93bc437944f4fd4452e2d74dd364f2e21e71f54bff" +
		"5cae82ab9c9df69ee86d2bc522363a0dabc521979b0deada1dbf9a42d5c4484e" +
		"0abcd06bfa53ddef3c1b20ee3fd59d7c25e41d2b669e1ef16e6f52c3164df4fb" +
		"7930e9e4e58857b6ac7d5f42d69f6d187763cf1d5503400487f55ba57e31cc7a" +
		"7135c886efb4318aed6a1e012d9e6832a907600a918130c46dc778f971ad0038" +
		"092999a333cb8b7a1a1db93d7140003c2a4ecea9f98d0acc0a8291cdcec97dcf" +
		"8ec9b55a7f88a46b4db5a851f44182e1c68a007e5e655f6affffffffffffffff"
)

// ffdheGroup is one RFC 7919 group.
type ffdheGroup struct {
	id       CurveID
	p        *bigmod.Modulus
	pBytes   []byte
	expBytes int // private exponent length (RFC 7919 5.2: at least 225, 275, 325 bits)
}

var ffdheGroups = func() map[CurveID]*ffdheGroup {
	m := map[CurveID]*ffdheGroup{}
	for _, g := range []struct {
		id  CurveID
		hex string
		exp int
	}{{FFDHE2048, ffdhe2048P, 32}, {FFDHE3072, ffdhe3072P, 40}, {FFDHE4096, ffdhe4096P, 48}} {
		b, err := hex.DecodeString(g.hex)
		if err != nil {
			panic(err)
		}
		mod, err := bigmod.NewModulus(b)
		if err != nil {
			panic(err)
		}
		m[g.id] = &ffdheGroup{id: g.id, p: mod, pBytes: b, expBytes: g.exp}
	}
	return m
}()

func isFFDHE(id CurveID) bool { return id == FFDHE2048 || id == FFDHE3072 || id == FFDHE4096 }

// ffdheGroupByParams finds the RFC 7919 group with prime p and generator
// g (leading zero bytes ignored); other groups are refused.
func ffdheGroupByParams(p, g []byte) *ffdheGroup {
	p, g = trimZeros(p), trimZeros(g)
	if len(g) != 1 || g[0] != 2 {
		return nil
	}
	for _, grp := range ffdheGroups {
		if slices.Equal(grp.pBytes, p) {
			return grp
		}
	}
	return nil
}

func trimZeros(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	return b
}

// generate returns a private exponent and the public value 2^x mod p
// (padded to the length of p).
func (g *ffdheGroup) generate(rand io.Reader) (priv, pub []byte, err error) {
	priv = make([]byte, g.expBytes)
	for {
		if _, err := io.ReadFull(rand, priv); err != nil {
			return nil, nil, err
		}
		if trimZeros(priv) != nil && len(trimZeros(priv)) > 1 {
			break
		}
	}
	two, err := bigmod.NewNat().SetBytes([]byte{2}, g.p)
	if err != nil {
		return nil, nil, err
	}
	y := bigmod.NewNat().Exp(two, priv, g.p)
	return priv, y.Bytes(g.p), nil
}

// shared returns peer^priv mod p, padded to the length of p. The peer
// value must satisfy 1 < y < p-1 (RFC 7919 5.1).
func (g *ffdheGroup) shared(priv, peer []byte) ([]byte, error) {
	if len(peer) > len(g.pBytes) {
		return nil, errors.New("tlsx: finite field DH public value too long")
	}
	y, err := bigmod.NewNat().SetBytes(peer, g.p) // fails unless y < p
	if err != nil {
		return nil, errors.New("tlsx: finite field DH public value not below p")
	}
	if y.IsZero() == 1 || y.IsOne() == 1 || y.IsMinusOne(g.p) == 1 {
		return nil, errors.New("tlsx: finite field DH public value out of range")
	}
	z := bigmod.NewNat().Exp(y, priv, g.p)
	if z.IsOne() == 1 {
		return nil, errors.New("tlsx: finite field DH shared secret is 1")
	}
	return z.Bytes(g.p), nil
}

// ffdheKeyExchange is a TLS 1.3 key exchange on an RFC 7919 group: key
// shares and the shared secret are padded to the length of p (RFC 8446
// 4.2.8.1, 7.4.1).
type ffdheKeyExchange struct{ g *ffdheGroup }

func (ke *ffdheKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	priv, pub, err := ke.g.generate(rand)
	if err != nil {
		return nil, nil, err
	}
	return &keySharePrivateKeys{x: priv}, []keyShare{{ke.g.id, pub}}, nil
}

func (ke *ffdheKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	if len(clientKeyShare) != len(ke.g.pBytes) {
		return nil, keyShare{}, errors.New("tlsx: finite field key share of the wrong length")
	}
	priv, pub, err := ke.g.generate(rand)
	if err != nil {
		return nil, keyShare{}, err
	}
	z, err := ke.g.shared(priv, clientKeyShare)
	if err != nil {
		return nil, keyShare{}, err
	}
	return z, keyShare{ke.g.id, pub}, nil
}

func (ke *ffdheKeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	if len(serverKeyShare) != len(ke.g.pBytes) || priv == nil || priv.x == nil {
		return nil, errors.New("tlsx: finite field key share of the wrong length")
	}
	return ke.g.shared(priv.x, serverKeyShare)
}

// brainpool groups.

func isBrainpool(id CurveID) bool {
	switch id {
	case BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1:
		return true
	}
	return false
}

func isTLS12OnlyGroup(id CurveID) bool { return isBrainpool(id) }

// firstTLS13Group is the first group of l usable in TLS 1.3 (a ClientHello
// offering TLS 1.2 and 1.3 lists both kinds).
func firstTLS13Group(l []CurveID) CurveID {
	for _, id := range l {
		if !isTLS12OnlyGroup(id) {
			return id
		}
	}
	return 0
}

func brainpoolCurve(id CurveID) elliptic.Curve {
	switch id {
	case BrainpoolP256r1, BrainpoolP256r1TLS13:
		return brainpool.P256r1()
	case BrainpoolP384r1, BrainpoolP384r1TLS13:
		return brainpool.P384r1()
	case BrainpoolP512r1, BrainpoolP512r1TLS13:
		return brainpool.P512r1()
	}
	return nil
}

// brainpoolKeyExchange is a TLS 1.3 key exchange on a brainpool curve
// (RFC 8734: uncompressed points, the x-coordinate as shared secret).
type brainpoolKeyExchange struct {
	id    CurveID
	curve elliptic.Curve
}

func (ke *brainpoolKeyExchange) keyShares(rand io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	priv, pub, err := brainpool.GenerateECDHKey(ke.curve, rand)
	if err != nil {
		return nil, nil, err
	}
	return &keySharePrivateKeys{x: priv}, []keyShare{{ke.id, pub}}, nil
}

func (ke *brainpoolKeyExchange) serverSharedSecret(rand io.Reader, clientKeyShare []byte) ([]byte, keyShare, error) {
	priv, pub, err := brainpool.GenerateECDHKey(ke.curve, rand)
	if err != nil {
		return nil, keyShare{}, err
	}
	z, err := brainpool.ECDH(ke.curve, priv, clientKeyShare)
	if err != nil {
		return nil, keyShare{}, err
	}
	return z, keyShare{ke.id, pub}, nil
}

func (ke *brainpoolKeyExchange) clientSharedSecret(priv *keySharePrivateKeys, serverKeyShare []byte) ([]byte, error) {
	if priv == nil || priv.x == nil {
		return nil, errors.New("tlsx: no brainpool key")
	}
	return brainpool.ECDH(ke.curve, priv.x, serverKeyShare)
}

// keyExchangeForCurveIDX gives the TLS 1.3 key exchanges tlsx adds.
func keyExchangeForCurveIDX(id CurveID) keyExchange {
	if id == 0 {
		return pskOnlyKeyExchange{} // TLS 1.3 psk_ke (x_psk.go)
	}
	if g := ffdheGroups[id]; g != nil {
		return &ffdheKeyExchange{g}
	}
	switch id {
	case BrainpoolP256r1TLS13, BrainpoolP384r1TLS13, BrainpoolP512r1TLS13:
		return &brainpoolKeyExchange{id, brainpoolCurve(id)}
	}
	return nil
}

// tlsxGroups are the groups tlsx adds, in their default preference order;
// none is used unless Config.CurvePreferences lists it.
var tlsxGroups = []CurveID{BrainpoolP256r1TLS13, BrainpoolP384r1TLS13, BrainpoolP512r1TLS13,
	BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1, FFDHE2048, FFDHE3072, FFDHE4096}

// curvePreferencesX adds the groups of Config.CurvePreferences that tlsx
// implements, after the upstream ones, in the Config's order.
func (c *Config) curvePreferencesX(prefs []CurveID) []CurveID {
	if c == nil {
		return prefs
	}
	for _, id := range c.CurvePreferences {
		if slices.Contains(tlsxGroups, id) && !slices.Contains(prefs, id) {
			prefs = append(prefs, id)
		}
	}
	return prefs
}

// generateKey makes the ECDHE key of a TLS 1.2 key agreement and returns
// the public point.
func (ka *ecdheKeyAgreement) generateKey(rand io.Reader) ([]byte, error) {
	if isBrainpool(ka.curveID) {
		priv, pub, err := brainpool.GenerateECDHKey(brainpoolCurve(ka.curveID), rand)
		if err != nil {
			return nil, err
		}
		ka.bpKey = priv
		return pub, nil
	}
	key, err := generateECDHEKey(rand, ka.curveID)
	if err != nil {
		return nil, err
	}
	ka.key = key
	return key.PublicKey().Bytes(), nil
}

// sharedSecret computes the ECDHE shared secret with the peer's point.
func (ka *ecdheKeyAgreement) sharedSecret(peer []byte) ([]byte, error) {
	if isBrainpool(ka.curveID) {
		return brainpool.ECDH(brainpoolCurve(ka.curveID), ka.bpKey, peer)
	}
	peerKey, err := ka.key.Curve().NewPublicKey(peer)
	if err != nil {
		return nil, err
	}
	return ka.key.ECDH(peerKey)
}

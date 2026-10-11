// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cB-Sigma/tlsx/internal/bigmod"
)

// Static Diffie-Hellman (RFC 5246 7.4.7.2, 8.1.2; RFC 5288 suite
// TLS_DH_RSA_WITH_AES_128_GCM_SHA256), which IEC 62351-4 names for MMS.
// The server's certificate carries its DH public key (X9.42
// dhpublicnumber, or PKCS #3 dhKeyAgreement), signed by its CA; there is
// no ServerKeyExchange. The client sends an explicit public value in
// ClientKeyExchange (fixed_dh client certificates are not supported). The
// suite is off by default: Config.CipherSuites must list it and the server
// needs Ext.StaticDHCertificate. TLS 1.2 only.

// TLS_DH_RSA_WITH_AES_128_GCM_SHA256 is the static DH suite (RFC 5288).
const TLS_DH_RSA_WITH_AES_128_GCM_SHA256 uint16 = 0x00a0

// suiteStaticDH marks a static DH suite (a tlsx cipherSuite flag).
const suiteStaticDH = 1 << 11

var (
	oidDHPublicNumber  = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}     // X9.42
	oidDHKeyAgreement  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 3, 1} // PKCS #3
	errStaticDHKey     = errors.New("tlsx: not a static DH key")
	minStaticDHModulus = 2048
)

// DHPublicKey is a finite field Diffie-Hellman public key with its domain
// parameters (Q may be nil for PKCS #3 keys).
type DHPublicKey struct {
	P, G, Q, Y *big.Int
}

// DHPrivateKey is a static DH private key (Ext.StaticDHCertificate's
// PrivateKey).
type DHPrivateKey struct {
	DHPublicKey
	X *big.Int
}

// Public returns the public half.
func (k *DHPrivateKey) Public() crypto.PublicKey { return &k.DHPublicKey }

type dhDomainParams struct {
	P, G, Q *big.Int
	Rest    asn1.RawContent `asn1:"optional"`
}

// parseDHSPKI reads a DH SubjectPublicKeyInfo.
func parseDHSPKI(der []byte) (*DHPublicKey, bool) {
	var s struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if rest, err := asn1.Unmarshal(der, &s); err != nil || len(rest) != 0 {
		return nil, false
	}
	k := &DHPublicKey{}
	switch {
	case s.Algorithm.Algorithm.Equal(oidDHPublicNumber):
		var p struct {
			P, G, Q *big.Int
			Rest    []asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(s.Algorithm.Parameters.FullBytes, &p); err != nil {
			return nil, false
		}
		k.P, k.G, k.Q = p.P, p.G, p.Q
	case s.Algorithm.Algorithm.Equal(oidDHKeyAgreement):
		var p struct {
			P, G *big.Int
			L    int `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(s.Algorithm.Parameters.FullBytes, &p); err != nil {
			return nil, false
		}
		k.P, k.G = p.P, p.G
	default:
		return nil, false
	}
	if _, err := asn1.Unmarshal(s.PublicKey.RightAlign(), &k.Y); err != nil || k.P == nil || k.G == nil {
		return nil, false
	}
	return k, k.check(k.Y) == nil
}

// check validates the parameters and a public value: a prime modulus of
// at least 2048 bits, 1 < y < p-1 and, with Q, y^q = 1 mod p.
func (k *DHPublicKey) check(y *big.Int) error {
	if k.P.BitLen() < minStaticDHModulus || !k.P.ProbablyPrime(20) {
		return fmt.Errorf("tlsx: DH modulus of %d bits (at least %d, prime)", k.P.BitLen(), minStaticDHModulus)
	}
	pm1 := new(big.Int).Sub(k.P, big.NewInt(1))
	if y == nil || y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pm1) >= 0 || k.G.Cmp(big.NewInt(1)) <= 0 || k.G.Cmp(pm1) >= 0 {
		return errors.New("tlsx: DH value out of range")
	}
	if k.Q != nil && new(big.Int).Exp(y, k.Q, k.P).Cmp(big.NewInt(1)) != 0 {
		return errors.New("tlsx: DH value not in the prime-order subgroup")
	}
	return nil
}

func (k *DHPublicKey) spki() ([]byte, error) {
	params, err := asn1.Marshal(struct{ P, G, Q *big.Int }{k.P, k.G, k.Q})
	if err != nil {
		return nil, err
	}
	y, _ := asn1.Marshal(k.Y)
	return asn1.Marshal(struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}{pkix.AlgorithmIdentifier{Algorithm: oidDHPublicNumber, Parameters: asn1.RawValue{FullBytes: params}}, asn1.BitString{Bytes: y, BitLength: 8 * len(y)}})
}

// GenerateStaticDHKey makes a key on the RFC 7919 ffdhe2048 group (Q =
// (P-1)/2).
func GenerateStaticDHKey(rand io.Reader) (*DHPrivateKey, error) {
	g := ffdheGroups[FFDHE2048]
	p := new(big.Int).SetBytes(g.pBytes)
	q := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	x, err := randInt(rand, q)
	if err != nil {
		return nil, err
	}
	k := &DHPrivateKey{DHPublicKey: DHPublicKey{P: p, G: big.NewInt(2), Q: q}, X: x}
	y, err := ctExp(k.G, x, p)
	if err != nil {
		return nil, err
	}
	k.Y = new(big.Int).SetBytes(y)
	return k, nil
}

func randInt(r io.Reader, max *big.Int) (*big.Int, error) {
	b := make([]byte, (max.BitLen()+7)/8)
	for {
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(b)
		if x.Cmp(big.NewInt(1)) > 0 && x.Cmp(max) < 0 {
			return x, nil
		}
	}
}

// MarshalStaticDHKey encodes the key as PKCS #8 (X9.42 dhpublicnumber),
// the "PRIVATE KEY" form OpenSSL writes for DH keys.
func MarshalStaticDHKey(k *DHPrivateKey) ([]byte, error) {
	params, err := asn1.Marshal(struct{ P, G, Q *big.Int }{k.P, k.G, k.Q})
	if err != nil {
		return nil, err
	}
	x, _ := asn1.Marshal(k.X)
	return asn1.Marshal(struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}{0, pkix.AlgorithmIdentifier{Algorithm: oidDHPublicNumber, Parameters: asn1.RawValue{FullBytes: params}}, x})
}

// ParseStaticDHKey reads a PKCS #8 DH private key (X9.42 or PKCS #3).
func ParseStaticDHKey(der []byte) (*DHPrivateKey, error) {
	var pk struct {
		Version    int
		Algorithm  pkix.AlgorithmIdentifier
		PrivateKey []byte
	}
	if rest, err := asn1.Unmarshal(der, &pk); err != nil || len(rest) != 0 {
		return nil, errStaticDHKey
	}
	k := &DHPrivateKey{}
	switch {
	case pk.Algorithm.Algorithm.Equal(oidDHPublicNumber):
		var p struct {
			P, G, Q *big.Int
			Rest    []asn1.RawValue `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(pk.Algorithm.Parameters.FullBytes, &p); err != nil {
			return nil, errStaticDHKey
		}
		k.P, k.G, k.Q = p.P, p.G, p.Q
	case pk.Algorithm.Algorithm.Equal(oidDHKeyAgreement):
		var p struct {
			P, G *big.Int
			L    int `asn1:"optional"`
		}
		if _, err := asn1.Unmarshal(pk.Algorithm.Parameters.FullBytes, &p); err != nil {
			return nil, errStaticDHKey
		}
		k.P, k.G = p.P, p.G
	default:
		return nil, errStaticDHKey
	}
	if _, err := asn1.Unmarshal(pk.PrivateKey, &k.X); err != nil || k.P == nil || k.G == nil {
		return nil, errStaticDHKey
	}
	y, err := ctExp(k.G, k.X, k.P)
	if err != nil {
		return nil, errStaticDHKey
	}
	k.Y = new(big.Int).SetBytes(y)
	if err := k.check(k.Y); err != nil {
		return nil, err
	}
	return k, nil
}

// CreateStaticDHCertificate issues a certificate for a DH public key (the
// Go x509 package cannot): template and parent as for
// x509.CreateCertificate, signed by signer (RSA or ECDSA, SHA-256 or
// SHA-384).
func CreateStaticDHCertificate(rand io.Reader, template, parent *x509.Certificate, pub *DHPublicKey, signer crypto.Signer) ([]byte, error) {
	if err := pub.check(pub.Y); err != nil {
		return nil, err
	}
	// Issue with a stand-in key, then put the DH key in and sign again.
	stand, err := ecdsa.GenerateKey(elliptic.P256(), rand)
	if err != nil {
		return nil, err
	}
	tmp, err := x509.CreateCertificate(rand, template, parent, &stand.PublicKey, signer)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(tmp)
	if err != nil {
		return nil, err
	}
	var tbs asn1.RawValue
	if _, err := asn1.Unmarshal(c.RawTBSCertificate, &tbs); err != nil {
		return nil, err
	}
	fields, err := rawElements(tbs.Bytes)
	if err != nil {
		return nil, err
	}
	spki, err := pub.spki()
	if err != nil {
		return nil, err
	}
	replaced := false
	for i, f := range fields {
		if bytes.Equal(f, c.RawSubjectPublicKeyInfo) {
			fields[i], replaced = spki, true
		}
	}
	if !replaced {
		return nil, errors.New("tlsx: SubjectPublicKeyInfo not found")
	}
	newTBS, _ := asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join(fields, nil)})
	var h crypto.Hash
	var digest []byte
	switch c.SignatureAlgorithm {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		s := sha256.Sum256(newTBS)
		h, digest = crypto.SHA256, s[:]
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		s := sha512.Sum384(newTBS)
		h, digest = crypto.SHA384, s[:]
	default:
		return nil, fmt.Errorf("tlsx: signature algorithm %s not supported for DH certificates", c.SignatureAlgorithm)
	}
	sig, err := signer.Sign(rand, digest, h)
	if err != nil {
		return nil, err
	}
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(tmp, &outer); err != nil {
		return nil, err
	}
	parts, err := rawElements(outer.Bytes)
	if err != nil || len(parts) != 3 {
		return nil, errors.New("tlsx: certificate structure")
	}
	bits, _ := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)})
	return asn1.Marshal(asn1.RawValue{Tag: asn1.TagSequence, IsCompound: true, Bytes: bytes.Join([][]byte{newTBS, parts[1], bits}, nil)})
}

func rawElements(b []byte) ([][]byte, error) {
	var out [][]byte
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			return nil, err
		}
		out, b = append(out, v.FullBytes), rest
	}
	return out, nil
}

// ctExp is base^exp mod p in constant time in exp (internal/bigmod); the
// exponent is padded to the length of p so its size does not show.
func ctExp(base, exp, p *big.Int) ([]byte, error) {
	m, err := bigmod.NewModulus(p.Bytes())
	if err != nil {
		return nil, err
	}
	b, err := bigmod.NewNat().SetBytes(base.Bytes(), m)
	if err != nil {
		return nil, err
	}
	e := exp.FillBytes(make([]byte, (p.BitLen()+7)/8))
	return trimZeros(bigmod.NewNat().Exp(b, e, m).Bytes(m)), nil // leading zeros stripped (RFC 5246 8.1.2)
}

func staticDHKA(version uint16) keyAgreement { return &staticDHKeyAgreement{} }

// staticDHKeyAgreement is DH_RSA with an explicit client public value.
type staticDHKeyAgreement struct{}

func (ka *staticDHKeyAgreement) generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, nil // the parameters are in the certificate
}

func (ka *staticDHKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	priv, ok := cert.PrivateKey.(*DHPrivateKey)
	if !ok {
		return nil, errStaticDHKey
	}
	s := cryptobyte.String(ckx.ciphertext)
	var yc []byte
	if !readUint16LengthPrefixed(&s, &yc) || !s.Empty() || len(yc) == 0 {
		return nil, errClientKeyExchange // fixed_dh (empty) is not supported
	}
	y := new(big.Int).SetBytes(yc)
	if priv.check(y) != nil {
		return nil, errClientKeyExchange
	}
	return ctExp(y, priv.X, priv.P)
}

func (ka *staticDHKeyAgreement) processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error {
	return errors.New("tlsx: ServerKeyExchange in a static DH handshake")
}

func (ka *staticDHKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	pub, ok := cert.PublicKey.(*DHPublicKey)
	if !ok {
		return nil, nil, errors.New("tlsx: the server certificate has no DH key for the static DH suite")
	}
	max := pub.Q
	if max == nil {
		max = new(big.Int).Sub(pub.P, big.NewInt(2))
	}
	x, err := randInt(config.rand(), max)
	if err != nil {
		return nil, nil, err
	}
	ycb, err := ctExp(pub.G, x, pub.P)
	if err != nil {
		return nil, nil, err
	}
	z, err := ctExp(pub.Y, x, pub.P)
	if err != nil {
		return nil, nil, err
	}
	yc := new(big.Int).SetBytes(ycb)
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(yc.FillBytes(make([]byte, (pub.P.BitLen()+7)/8))) })
	return z, &clientKeyExchangeMsg{ciphertext: b.BytesOrPanic()}, nil
}

// staticDHServerCert switches the server to its DH certificate once the
// static DH suite is chosen.
func (hs *serverHandshakeState) staticDHServerCert() {
	if hs.suite != nil && hs.suite.flags&suiteStaticDH != 0 {
		hs.cert = hs.c.config.Ext.StaticDHCertificate
	}
}

// staticDHPeerKeyOK lets a client accept a DH server certificate for the
// static DH suite only.
func staticDHPeerKeyOK(c *Conn, pub any) bool {
	_, ok := pub.(*DHPublicKey)
	if !ok {
		return false
	}
	s := cipherSuiteByID(c.cipherSuite)
	return s != nil && s.flags&suiteStaticDH != 0
}

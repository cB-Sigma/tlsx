// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package brainpool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
)

// DER encodings of brainpool keys: SubjectPublicKeyInfo (RFC 5480),
// ECPrivateKey (RFC 5915) and PKCS#8 (RFC 5208 / RFC 5958). Parsing and
// marshalling are variable time.

// The ASN.1 structures below are the same as crypto/x509's (publicKeyInfo in
// x509.go, ecPrivateKey in sec1.go, pkcs8 in pkcs8.go; Copyright The Go
// Authors, see NOTICE), which transcribe RFC 5280, RFC 5915 and RFC 5208.

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
	Attributes asn1.RawValue `asn1:"optional,tag:0"`
	PublicKey  asn1.RawValue `asn1:"optional,tag:1"`
}

func algorithmFor(c *curve) (pkix.AlgorithmIdentifier, error) {
	params, err := asn1.Marshal(c.oid)
	if err != nil {
		return pkix.AlgorithmIdentifier{}, err
	}
	return pkix.AlgorithmIdentifier{Algorithm: oidPublicKeyECDSA, Parameters: asn1.RawValue{FullBytes: params}}, nil
}

// curveFromAlgorithm returns the brainpool curve named in an id-ecPublicKey
// AlgorithmIdentifier.
func curveFromAlgorithm(alg pkix.AlgorithmIdentifier) (*curve, error) {
	if !alg.Algorithm.Equal(oidPublicKeyECDSA) {
		return nil, errors.New("brainpool: not an elliptic-curve key")
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(alg.Parameters.FullBytes, &oid)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("brainpool: key parameters are not a named curve")
	}
	c, ok := CurveForOID(oid)
	if !ok {
		return nil, errors.New("brainpool: key is not on a brainpool curve")
	}
	return c.(*curve), nil
}

func pointBytes(pub *ecdsa.PublicKey) (*curve, []byte, error) {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil, nil, errors.New("brainpool: nil public key")
	}
	c, err := toCurve(pub.Curve)
	if err != nil {
		return nil, nil, err
	}
	if !c.IsOnCurve(pub.X, pub.Y) {
		return nil, nil, errors.New("brainpool: public key not on curve")
	}
	return c, elliptic.Marshal(c, pub.X, pub.Y), nil
}

func publicKeyFromPoint(c *curve, b []byte) (*ecdsa.PublicKey, error) {
	if _, err := c.pointFromUncompressed(b); err != nil {
		return nil, err
	}
	return &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(b[1 : 1+c.size]),
		Y:     new(big.Int).SetBytes(b[1+c.size:]),
	}, nil
}

// ParsePKIXPublicKey parses a DER SubjectPublicKeyInfo holding an
// id-ecPublicKey on a brainpool named curve (uncompressed point).
func ParsePKIXPublicKey(spki []byte) (*ecdsa.PublicKey, error) {
	var info publicKeyInfo
	rest, err := asn1.Unmarshal(spki, &info)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("brainpool: trailing data after public key")
	}
	c, err := curveFromAlgorithm(info.Algorithm)
	if err != nil {
		return nil, err
	}
	if info.PublicKey.BitLength != 8*len(info.PublicKey.Bytes) {
		return nil, errors.New("brainpool: public key bit string not octet aligned")
	}
	return publicKeyFromPoint(c, info.PublicKey.Bytes)
}

// MarshalPKIXPublicKey returns the DER SubjectPublicKeyInfo of a brainpool
// public key.
func MarshalPKIXPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	c, pt, err := pointBytes(pub)
	if err != nil {
		return nil, err
	}
	alg, err := algorithmFor(c)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(publicKeyInfo{Algorithm: alg, PublicKey: asn1.BitString{Bytes: pt, BitLength: 8 * len(pt)}})
}

// parseECPrivateKey parses an RFC 5915 structure. named, if non-nil, is the
// curve given by an enclosing PKCS#8 AlgorithmIdentifier.
func parseECPrivateKey(named *curve, der []byte) (*PrivateKey, error) {
	var k ecPrivateKey
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("brainpool: trailing data after private key")
	}
	if k.Version != 1 {
		return nil, errors.New("brainpool: unknown EC private key version")
	}
	c := named
	if len(k.NamedCurveOID) > 0 {
		ic, ok := CurveForOID(k.NamedCurveOID)
		if !ok {
			return nil, errors.New("brainpool: private key is not on a brainpool curve")
		}
		if c != nil && ic.(*curve) != c {
			return nil, errors.New("brainpool: private key curve mismatch")
		}
		c = ic.(*curve)
	}
	if c == nil {
		return nil, errors.New("brainpool: private key names no curve")
	}
	priv, err := NewPrivateKey(c, k.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(k.PublicKey.Bytes) > 0 {
		pub, err := publicKeyFromPoint(c, k.PublicKey.Bytes)
		if err != nil {
			return nil, err
		}
		if pub.X.Cmp(priv.pub.X) != 0 || pub.Y.Cmp(priv.pub.Y) != 0 {
			return nil, errors.New("brainpool: embedded public key does not match private key")
		}
	}
	return priv, nil
}

// ParseECPrivateKey parses an RFC 5915 (SEC 1) ECPrivateKey, or the same
// wrapped in PKCS#8, on a brainpool curve.
func ParseECPrivateKey(der []byte) (*PrivateKey, error) {
	k, err := parseECPrivateKey(nil, der)
	if err == nil {
		return k, nil
	}
	if k8, err8 := ParsePKCS8PrivateKey(der); err8 == nil {
		return k8, nil
	}
	return nil, err
}

// ParsePKCS8PrivateKey parses a PKCS#8 PrivateKeyInfo holding a brainpool
// EC private key.
func ParsePKCS8PrivateKey(der []byte) (*PrivateKey, error) {
	var p pkcs8
	rest, err := asn1.Unmarshal(der, &p)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("brainpool: trailing data after PKCS#8 key")
	}
	if p.Version != 0 && p.Version != 1 {
		return nil, errors.New("brainpool: unknown PKCS#8 version")
	}
	c, err := curveFromAlgorithm(p.Algo)
	if err != nil {
		return nil, err
	}
	return parseECPrivateKey(c, p.PrivateKey)
}

func (k *PrivateKey) ecPrivateKey(withCurve bool) ecPrivateKey {
	pt := elliptic.Marshal(k.c, k.pub.X, k.pub.Y)
	out := ecPrivateKey{
		Version:    1,
		PrivateKey: append([]byte(nil), k.d...),
		PublicKey:  asn1.BitString{Bytes: pt, BitLength: 8 * len(pt)},
	}
	if withCurve {
		out.NamedCurveOID = k.c.oid
	}
	return out
}

// MarshalECPrivateKey returns the RFC 5915 ECPrivateKey DER encoding
// (with the named curve and the public key).
func MarshalECPrivateKey(k *PrivateKey) ([]byte, error) {
	if k == nil || k.c == nil {
		return nil, errors.New("brainpool: nil private key")
	}
	return asn1.Marshal(k.ecPrivateKey(true))
}

// MarshalPKCS8PrivateKey returns the PKCS#8 PrivateKeyInfo DER encoding; the
// curve is named in the AlgorithmIdentifier, not in the inner structure.
func MarshalPKCS8PrivateKey(k *PrivateKey) ([]byte, error) {
	if k == nil || k.c == nil {
		return nil, errors.New("brainpool: nil private key")
	}
	inner, err := asn1.Marshal(k.ecPrivateKey(false))
	if err != nil {
		return nil, err
	}
	alg, err := algorithmFor(k.c)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(pkcs8{Version: 0, Algo: alg, PrivateKey: inner})
}

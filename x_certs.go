// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"slices"
	"strconv"
	"sync"

	"github.com/cB-Sigma/tlsx/internal/brainpool"
)

// Certificates and keys crypto/x509 does not handle:
//
//   - RSASSA-PSS public keys (OID id-RSASSA-PSS, RFC 4055), for the
//     rsa_pss_pss_* signature schemes (RFC 8446 4.2.3) and as CA keys.
//     crypto/x509 parses such a certificate with PublicKey nil and
//     PublicKeyAlgorithm UnknownPublicKeyAlgorithm; ParseCertificate fills
//     PublicKey with the *rsa.PublicKey and sets the algorithm to RSA, so
//     crypto/x509 verifies what such a CA signed, and records the key (by
//     its value) as a PSS key with its hash restriction. A CA pool must be
//     filled with AppendCertsFromPEM (or ParseCertificate and AddCert) for
//     a PSS CA to be usable: a pool crypto/x509 fills itself cannot use it.
//   - ECDSA keys on the brainpool curves (internal/brainpool).

var oidRSASSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// spki is crypto/x509's publicKeyInfo (x509.go) without the Raw field.
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
type spki struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pssParams struct {
	Hash pkix.AlgorithmIdentifier `asn1:"explicit,tag:0,optional"`
}

// pssKeyInfo records the RSASSA-PSS keys seen, by value, with the hash
// their parameters bind them to (0: any). Keyed by value so it stays
// bounded by the distinct keys, not by the certificates parsed.
var pssKeyInfo sync.Map // pssKeyID -> crypto.Hash

func pssKeyID(pub *rsa.PublicKey) string { return strconv.Itoa(pub.E) + "/" + string(pub.N.Bytes()) }

// ParseCertificate parses a DER certificate like x509.ParseCertificate and
// also accepts RSASSA-PSS and brainpool public keys.
func ParseCertificate(der []byte) (*x509.Certificate, error) { return parseCertificateX(der) }

func parseCertificateX(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		if brainpool.IsBrainpoolCertificate(der) {
			return brainpool.ParseCertificate(der)
		}
		return nil, err
	}
	if cert.PublicKeyAlgorithm == x509.UnknownPublicKeyAlgorithm && cert.PublicKey == nil {
		if pub, h, ok := parsePSSSPKI(cert.RawSubjectPublicKeyInfo); ok {
			cert.PublicKey = pub
			cert.PublicKeyAlgorithm = x509.RSA
			pssKeyInfo.Store(pssKeyID(pub), h)
		} else if dh, ok := parseDHSPKI(cert.RawSubjectPublicKeyInfo); ok {
			cert.PublicKey = dh // static DH (x_staticdh.go)
		}
	}
	return cert, nil
}

func parsePSSSPKI(der []byte) (*rsa.PublicKey, crypto.Hash, bool) {
	var s spki
	if rest, err := asn1.Unmarshal(der, &s); err != nil || len(rest) != 0 || !s.Algorithm.Algorithm.Equal(oidRSASSAPSS) {
		return nil, 0, false
	}
	pub, err := x509.ParsePKCS1PublicKey(s.PublicKey.RightAlign())
	if err != nil {
		return nil, 0, false
	}
	var h crypto.Hash
	if len(s.Algorithm.Parameters.FullBytes) > 0 {
		var p pssParams
		if _, err := asn1.Unmarshal(s.Algorithm.Parameters.FullBytes, &p); err != nil {
			return nil, 0, false
		}
		switch {
		case p.Hash.Algorithm.Equal(oidSHA256):
			h = crypto.SHA256
		case p.Hash.Algorithm.Equal(oidSHA384):
			h = crypto.SHA384
		case p.Hash.Algorithm.Equal(oidSHA512):
			h = crypto.SHA512
		case len(p.Hash.Algorithm) == 0:
			h = crypto.SHA1 // RFC 4055 default: no TLS scheme matches
		default:
			return nil, 0, false
		}
	}
	return pub, h, true
}

// IsRSAPSSKey reports whether cert (parsed by ParseCertificate) has an
// RSASSA-PSS public key.
func IsRSAPSSKey(cert *x509.Certificate) bool {
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}
	// The certificate's own SubjectPublicKeyInfo decides. The registry
	// (by key value) is only for certificates without one: an
	// rsaEncryption certificate for the same key is not a PSS key.
	if len(cert.RawSubjectPublicKeyInfo) > 0 {
		_, _, pss := parsePSSSPKI(cert.RawSubjectPublicKeyInfo)
		return pss
	}
	_, ok = pssKeyInfo.Load(pssKeyID(pub))
	return ok
}

// checkPeerPSSKeyX refuses a use of the peer's RSASSA-PSS key other than
// an rsa_pss_pss signature scheme the key allows. RFC 4055 (section 1.2)
// restricts an id-RSASSA-PSS key to RSASSA-PSS signatures, and RFC 8446
// (section 4.2.3, which applies to TLS 1.2 too) to the rsa_pss_pss
// schemes. scheme 0 stands for the uses without a scheme: RSA key
// transport and the fixed signatures of TLS 1.0 and 1.1. crypto/x509
// cannot parse these keys, so crypto/tls never meets one.
func checkPeerPSSKeyX(cert *x509.Certificate, scheme SignatureScheme) error {
	if cert == nil || !IsRSAPSSKey(cert) {
		return nil
	}
	if scheme == 0 {
		return errors.New("tlsx: an RSASSA-PSS certificate key cannot be used for RSA key exchange or TLS 1.0 and 1.1 signatures")
	}
	_, h, _ := parsePSSSPKI(cert.RawSubjectPublicKeyInfo)
	if !slices.Contains(pssSchemesFor(cert.PublicKey.(*rsa.PublicKey), h), scheme) {
		return errors.New("tlsx: an RSASSA-PSS certificate key cannot sign with " + scheme.String())
	}
	return nil
}

// ownPSSKeyX reports whether the leaf of c has an RSASSA-PSS key.
func ownPSSKeyX(c *Certificate) bool {
	if c == nil || len(c.Certificate) == 0 {
		return false
	}
	leaf := c.Leaf
	if leaf == nil || leaf.PublicKey == nil {
		leaf, _ = parseCertificateX(c.Certificate[0])
	}
	return leaf != nil && IsRSAPSSKey(leaf)
}

// AppendCertsFromPEM adds the PEM certificates to pool like
// x509.CertPool.AppendCertsFromPEM, parsing them with ParseCertificate (so
// RSASSA-PSS and brainpool CA keys work).
func AppendCertsFromPEM(pool *x509.CertPool, pemCerts []byte) bool {
	ok := false
	for len(pemCerts) > 0 {
		var blk *pem.Block
		if blk, pemCerts = pem.Decode(pemCerts); blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := parseCertificateX(blk.Bytes)
		if err != nil {
			continue
		}
		pool.AddCert(c)
		ok = true
	}
	return ok
}

// pssSchemes are the rsa_pss_pss schemes a PSS key of size bytes can
// sign, restricted to hash h if the key's parameters name one.
func pssSchemes(pub *rsa.PublicKey) []SignatureScheme {
	var h crypto.Hash
	if v, ok := pssKeyInfo.Load(pssKeyID(pub)); ok {
		h = v.(crypto.Hash)
	}
	return pssSchemesFor(pub, h)
}

// pssSchemesFor is pssSchemes for a key bound to hash h (0: any).
func pssSchemesFor(pub *rsa.PublicKey, h crypto.Hash) []SignatureScheme {
	var out []SignatureScheme
	for _, s := range []struct {
		scheme SignatureScheme
		hash   crypto.Hash
	}{{PSSPSSWithSHA256, crypto.SHA256}, {PSSPSSWithSHA384, crypto.SHA384}, {PSSPSSWithSHA512, crypto.SHA512}} {
		if (h == 0 || h == s.hash) && pub.Size() >= s.hash.Size()*2+2 {
			out = append(out, s.scheme)
		}
	}
	return out
}

// brainpoolScheme is the TLS 1.3 scheme of a brainpool key.
func brainpoolScheme(pub *ecdsa.PublicKey) (SignatureScheme, bool) {
	switch pub.Curve {
	case brainpool.P256r1():
		return ECDSABrainpoolP256r1TLS13WithSHA256, true
	case brainpool.P384r1():
		return ECDSABrainpoolP384r1TLS13WithSHA384, true
	case brainpool.P512r1():
		return ECDSABrainpoolP512r1TLS13WithSHA512, true
	}
	return 0, false
}

// signatureSchemesForCertificateX is signatureSchemesForPublicKey for a
// peer's certificate, with PSS and brainpool keys.
func signatureSchemesForCertificateX(version uint16, cert *x509.Certificate) []SignatureScheme {
	if IsRSAPSSKey(cert) {
		return pssSchemes(cert.PublicKey.(*rsa.PublicKey))
	}
	if pub, ok := cert.PublicKey.(*ecdsa.PublicKey); ok && version >= VersionTLS13 {
		if s, ok := brainpoolScheme(pub); ok {
			return []SignatureScheme{s}
		}
	}
	return signatureSchemesForPublicKey(version, cert.PublicKey)
}

// signatureSchemesForOwnX is the same for our own certificate.
func signatureSchemesForOwnX(version uint16, c *Certificate, pub crypto.PublicKey) []SignatureScheme {
	if rsaPub, ok := pub.(*rsa.PublicKey); ok && len(c.Certificate) > 0 {
		leaf := c.Leaf
		if leaf == nil || leaf.PublicKey == nil {
			leaf, _ = parseCertificateX(c.Certificate[0])
		}
		if leaf != nil && IsRSAPSSKey(leaf) {
			return pssSchemes(rsaPub) // same key value as the leaf's
		}
	}
	if ecPub, ok := pub.(*ecdsa.PublicKey); ok && version >= VersionTLS13 {
		if s, ok := brainpoolScheme(ecPub); ok {
			return []SignatureScheme{s}
		}
	}
	return signatureSchemesForPublicKey(version, pub)
}

// typeAndHashX covers the schemes tlsx adds.
func typeAndHashX(s SignatureScheme) (uint8, crypto.Hash, bool) {
	switch s {
	case PSSPSSWithSHA256:
		return signatureRSAPSS, crypto.SHA256, true
	case PSSPSSWithSHA384:
		return signatureRSAPSS, crypto.SHA384, true
	case PSSPSSWithSHA512:
		return signatureRSAPSS, crypto.SHA512, true
	case ECDSABrainpoolP256r1TLS13WithSHA256:
		return signatureECDSA, crypto.SHA256, true
	case ECDSABrainpoolP384r1TLS13WithSHA384:
		return signatureECDSA, crypto.SHA384, true
	case ECDSABrainpoolP512r1TLS13WithSHA512:
		return signatureECDSA, crypto.SHA512, true
	}
	return 0, 0, false
}

// pkcs8 is the same structure as crypto/x509's (pkcs8.go; Copyright The Go
// Authors, see NOTICE), a transcription of RFC 5208.
type pkcs8 struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

// parsePrivateKeyX parses the keys parsePrivateKey does not: PKCS#8
// RSASSA-PSS keys (as *rsa.PrivateKey) and brainpool keys.
// parsePrivateKeyX's errors reuse Go's text "tls: failed to parse private key"
// (crypto/tls/tls.go). Copyright The Go Authors, BSD-3-Clause; see NOTICE.
func parsePrivateKeyX(der []byte) (crypto.PrivateKey, error) {
	var k pkcs8
	if rest, err := asn1.Unmarshal(der, &k); err == nil && len(rest) == 0 && k.Algo.Algorithm.Equal(oidRSASSAPSS) {
		return x509.ParsePKCS1PrivateKey(k.PrivateKey)
	}
	if key, err := brainpool.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := brainpool.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("tls: failed to parse private key")
}

// ownKeyMatches checks a private key tlsx adds against the certificate's
// public key.
func ownKeyMatches(priv crypto.PrivateKey, pub crypto.PublicKey) bool {
	if bp, ok := priv.(*brainpool.PrivateKey); ok {
		p, ok := pub.(*ecdsa.PublicKey)
		return ok && bp.Public().(*ecdsa.PublicKey).Equal(p)
	}
	return false
}

// GenerateBrainpoolKey makes an ECDSA key on the brainpool curve of id
// (BrainpoolP256r1, P384r1 or P512r1, either code point), for tests and
// tooling. Its Sign is constant time in the key (internal/brainpool).
func GenerateBrainpoolKey(id CurveID, rand io.Reader) (crypto.Signer, error) {
	c := brainpoolCurve(id)
	if c == nil {
		return nil, errors.New("tlsx: not a brainpool curve")
	}
	return brainpool.GenerateKey(c, rand)
}

// CreateCertificate is x509.CreateCertificate that also takes brainpool
// public and signing keys.
func CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.Signer) ([]byte, error) {
	return brainpool.CreateCertificate(rand, template, parent, pub, priv)
}

// MarshalPKCS8PrivateKey is x509.MarshalPKCS8PrivateKey that also takes
// brainpool keys.
func MarshalPKCS8PrivateKey(k crypto.PrivateKey) ([]byte, error) {
	if bp, ok := k.(*brainpool.PrivateKey); ok {
		return brainpool.MarshalPKCS8PrivateKey(bp)
	}
	return x509.MarshalPKCS8PrivateKey(k)
}

// certificateStaples lists the OCSP responses of a received certificate
// chain by position.
func certificateStaples(c Certificate) [][]byte {
	if c.OCSPStaple == nil && !hasStaples(c.ChainOCSPStaples) {
		return nil
	}
	return append([][]byte{c.OCSPStaple}, c.ChainOCSPStaples...)
}

func hasStaples(l [][]byte) bool {
	return slices.ContainsFunc(l, func(b []byte) bool { return len(b) > 0 })
}

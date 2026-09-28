// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

// X.509 support. crypto/x509 refuses SubjectPublicKeyInfo on curves it does
// not know and cannot marshal such keys or sign with them. We work around
// that by letting crypto/x509 handle a copy of the certificate whose SPKI is a
// P-256 placeholder, and splicing the real SPKI (and, when creating, the real
// signature) back in. Verification of brainpool signatures then goes through
// crypto/ecdsa's generic path, which calls this package's elliptic.Curve
// methods.

// placeholderSPKI is a valid P-256 SubjectPublicKeyInfo (the P-256 base
// point); its only purpose is to let crypto/x509 parse the rest of a
// certificate.
var placeholderSPKI = func() []byte {
	c := elliptic.P256()
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: c, X: c.Params().Gx, Y: c.Params().Gy})
	if err != nil {
		panic(err)
	}
	return der
}()

// certParts splits a DER certificate into its TBS element list and the
// remaining outer elements. It re-encodes nothing.
type certParts struct {
	tbsElems  []asn1.RawValue // elements inside TBSCertificate, in order
	spkiIndex int             // index of subjectPublicKeyInfo in tbsElems
	tbsFull   []byte          // the full TBSCertificate element
	sigAlg    asn1.RawValue
	sigValue  asn1.RawValue
}

func splitCertificate(der []byte) (*certParts, error) {
	var outer asn1.RawValue
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 || outer.Class != asn1.ClassUniversal || outer.Tag != asn1.TagSequence {
		return nil, errors.New("brainpool: malformed certificate")
	}
	var tbs, sigAlg, sigValue asn1.RawValue
	in := outer.Bytes
	for _, dst := range []*asn1.RawValue{&tbs, &sigAlg, &sigValue} {
		if in, err = asn1.Unmarshal(in, dst); err != nil {
			return nil, err
		}
	}
	if len(in) != 0 || tbs.Tag != asn1.TagSequence {
		return nil, errors.New("brainpool: malformed certificate")
	}
	p := &certParts{tbsFull: tbs.FullBytes, sigAlg: sigAlg, sigValue: sigValue}
	in = tbs.Bytes
	for len(in) > 0 {
		var e asn1.RawValue
		if in, err = asn1.Unmarshal(in, &e); err != nil {
			return nil, err
		}
		p.tbsElems = append(p.tbsElems, e)
	}
	// version [0] EXPLICIT is optional; then serial, signature, issuer,
	// validity, subject, subjectPublicKeyInfo.
	p.spkiIndex = 5
	if len(p.tbsElems) > 0 && p.tbsElems[0].Class == asn1.ClassContextSpecific && p.tbsElems[0].Tag == 0 {
		p.spkiIndex = 6
	}
	if len(p.tbsElems) <= p.spkiIndex {
		return nil, errors.New("brainpool: malformed TBSCertificate")
	}
	return p, nil
}

func (p *certParts) spki() []byte { return p.tbsElems[p.spkiIndex].FullBytes }

// tbsWithSPKI returns the TBSCertificate re-encoded with spki replacing the
// subjectPublicKeyInfo.
func (p *certParts) tbsWithSPKI(spki []byte) ([]byte, error) {
	var content []byte
	for i, e := range p.tbsElems {
		if i == p.spkiIndex {
			content = append(content, spki...)
		} else {
			content = append(content, e.FullBytes...)
		}
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
}

func assembleCertificate(tbs, sigAlg, sigValue []byte) ([]byte, error) {
	content := append(append(append([]byte(nil), tbs...), sigAlg...), sigValue...)
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
}

// IsBrainpoolCertificate reports whether der is a certificate whose subject
// public key is on a brainpool curve.
func IsBrainpoolCertificate(der []byte) bool {
	p, err := splitCertificate(der)
	if err != nil {
		return false
	}
	_, err = ParsePKIXPublicKey(p.spki())
	return err == nil
}

// ParseCertificate parses a DER certificate. Certificates crypto/x509 accepts
// are returned as it parses them. A certificate with a brainpool subject key
// is parsed with a placeholder key, after which Raw, RawTBSCertificate and
// RawSubjectPublicKeyInfo are the original bytes and PublicKey is the
// brainpool *ecdsa.PublicKey.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err == nil {
		return cert, nil
	}
	p, perr := splitCertificate(der)
	if perr != nil {
		return nil, err
	}
	pub, perr := ParsePKIXPublicKey(p.spki())
	if perr != nil {
		return nil, err // not a brainpool key: report crypto/x509's error
	}
	tbs, perr := p.tbsWithSPKI(placeholderSPKI)
	if perr != nil {
		return nil, perr
	}
	patched, perr := assembleCertificate(tbs, p.sigAlg.FullBytes, p.sigValue.FullBytes)
	if perr != nil {
		return nil, perr
	}
	cert, err = x509.ParseCertificate(patched)
	if err != nil {
		return nil, err
	}
	raw := append([]byte(nil), der...)
	rp, _ := splitCertificate(raw)
	cert.Raw = raw
	cert.RawTBSCertificate = rp.tbsFull
	cert.RawSubjectPublicKeyInfo = rp.spki()
	// Point the other raw fields into the original bytes too (same content).
	if len(rp.tbsElems) > rp.spkiIndex {
		cert.RawIssuer = rp.tbsElems[rp.spkiIndex-3].FullBytes
		cert.RawSubject = rp.tbsElems[rp.spkiIndex-1].FullBytes
	}
	cert.PublicKey = pub
	cert.PublicKeyAlgorithm = x509.ECDSA
	return cert, nil
}

func brainpoolPublic(pub crypto.PublicKey) (*ecdsa.PublicKey, bool) {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok || k == nil || !IsBrainpool(k.Curve) {
		return nil, false
	}
	return k, true
}

func sigAlgForBrainpool(k *ecdsa.PublicKey) x509.SignatureAlgorithm {
	switch k.Curve.Params().BitSize {
	case 256:
		return x509.ECDSAWithSHA256
	case 384:
		return x509.ECDSAWithSHA384
	default:
		return x509.ECDSAWithSHA512
	}
}

// signTBS signs tbs with signer for the given algorithm.
func signTBS(rand io.Reader, signer crypto.Signer, alg x509.SignatureAlgorithm, tbs []byte) ([]byte, error) {
	var h crypto.Hash
	pss := false
	switch alg {
	case x509.ECDSAWithSHA256, x509.SHA256WithRSA:
		h = crypto.SHA256
	case x509.ECDSAWithSHA384, x509.SHA384WithRSA:
		h = crypto.SHA384
	case x509.ECDSAWithSHA512, x509.SHA512WithRSA:
		h = crypto.SHA512
	case x509.SHA256WithRSAPSS:
		h, pss = crypto.SHA256, true
	case x509.SHA384WithRSAPSS:
		h, pss = crypto.SHA384, true
	case x509.SHA512WithRSAPSS:
		h, pss = crypto.SHA512, true
	case x509.PureEd25519:
		return signer.Sign(rand, tbs, crypto.Hash(0))
	default:
		return nil, fmt.Errorf("brainpool: unsupported signature algorithm %v", alg)
	}
	hh := h.New()
	hh.Write(tbs)
	digest := hh.Sum(nil)
	var opts crypto.SignerOpts = h
	if pss {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
	}
	return signer.Sign(rand, digest, opts)
}

// CreateCertificate is x509.CreateCertificate for templates where pub and/or
// signer are brainpool keys. When neither is, it calls x509.CreateCertificate
// directly. A brainpool signer signs with ECDSA and SHA-256, SHA-384 or
// SHA-512 for 256-, 384- and 512-bit keys unless template.SignatureAlgorithm
// names another ECDSA algorithm.
func CreateCertificate(rand io.Reader, template, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) ([]byte, error) {
	if template == nil || parent == nil || signer == nil {
		return nil, errors.New("brainpool: nil template, parent or signer")
	}
	if rand == nil {
		rand = crand.Reader
	}
	bpPub, isBPPub := brainpoolPublic(pub)
	bpSigner, isBPSigner := brainpoolPublic(signer.Public())
	if !isBPPub && !isBPSigner {
		return x509.CreateCertificate(rand, template, parent, pub, signer)
	}

	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := *template
	par := *parent
	if parent == template {
		// Self-signed: keep the shared identity x509 relies on.
		par = tmpl
	}

	xpub := pub
	var realSPKI []byte
	if isBPPub {
		if realSPKI, err = MarshalPKIXPublicKey(bpPub); err != nil {
			return nil, err
		}
		xpub = &placeholder.PublicKey
		if len(tmpl.SubjectKeyId) == 0 {
			// Key identifier from the real key (RFC 5280 4.2.1.2 method 1),
			// not from the placeholder x509 would otherwise hash.
			var info publicKeyInfo
			if _, err := asn1.Unmarshal(realSPKI, &info); err != nil {
				return nil, err
			}
			sum := sha1.Sum(info.PublicKey.Bytes)
			tmpl.SubjectKeyId = sum[:]
			if parent == template {
				par.SubjectKeyId = sum[:]
			}
		}
	}

	var xsigner crypto.Signer = signer
	if isBPSigner {
		switch tmpl.SignatureAlgorithm {
		case x509.UnknownSignatureAlgorithm:
			tmpl.SignatureAlgorithm = sigAlgForBrainpool(bpSigner)
		case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		default:
			return nil, fmt.Errorf("brainpool: signature algorithm %v cannot be used with a brainpool key", tmpl.SignatureAlgorithm)
		}
		xsigner = placeholder
		par.PublicKey = &placeholder.PublicKey
	}

	tmpDER, err := x509.CreateCertificate(rand, &tmpl, &par, xpub, xsigner)
	if err != nil {
		return nil, err
	}
	tmpCert, err := x509.ParseCertificate(tmpDER)
	if err != nil {
		return nil, err
	}
	parts, err := splitCertificate(tmpDER)
	if err != nil {
		return nil, err
	}
	tbs := parts.tbsFull
	if isBPPub {
		if tbs, err = parts.tbsWithSPKI(realSPKI); err != nil {
			return nil, err
		}
	}
	sig, err := signTBS(rand, signer, tmpCert.SignatureAlgorithm, tbs)
	if err != nil {
		return nil, err
	}
	if isBPSigner {
		h := map[x509.SignatureAlgorithm]crypto.Hash{
			x509.ECDSAWithSHA256: crypto.SHA256, x509.ECDSAWithSHA384: crypto.SHA384, x509.ECDSAWithSHA512: crypto.SHA512,
		}[tmpCert.SignatureAlgorithm]
		hh := h.New()
		hh.Write(tbs)
		if !Verify(bpSigner, hh.Sum(nil), sig) {
			return nil, errors.New("brainpool: signer produced an invalid signature")
		}
	}
	sigValue, err := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)})
	if err != nil {
		return nil, err
	}
	return assembleCertificate(tbs, parts.sigAlg.FullBytes, sigValue)
}

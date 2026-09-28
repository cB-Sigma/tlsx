// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
)

// PKCS #10 certification requests (RFC 2986) for brainpool keys, the
// counterpart of CreateCertificate: crypto/x509 builds the request around a
// P-256 placeholder key, the real SubjectPublicKeyInfo is spliced into the
// CertificationRequestInfo, and the brainpool key signs it (F-1024).

// csrParts splits a DER certification request into the elements of its
// CertificationRequestInfo (version, subject, subjectPKInfo, attributes)
// and its signature algorithm and value.
type csrParts struct {
	infoElems []asn1.RawValue
	infoFull  []byte
	sigAlg    asn1.RawValue
	sigValue  asn1.RawValue
}

const csrSPKIIndex = 2 // version, subject, subjectPKInfo, attributes

func splitCSR(der []byte) (*csrParts, error) {
	var outer asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &outer); err != nil || len(rest) != 0 || outer.Tag != asn1.TagSequence {
		return nil, errors.New("brainpool: not a certification request")
	}
	p := &csrParts{}
	var info asn1.RawValue
	rest, err := asn1.Unmarshal(outer.Bytes, &info)
	if err != nil {
		return nil, err
	}
	if rest, err = asn1.Unmarshal(rest, &p.sigAlg); err != nil {
		return nil, err
	}
	if rest, err = asn1.Unmarshal(rest, &p.sigValue); err != nil || len(rest) != 0 {
		return nil, errors.New("brainpool: malformed certification request")
	}
	p.infoFull = info.FullBytes
	for b := info.Bytes; len(b) > 0; {
		var e asn1.RawValue
		if b, err = asn1.Unmarshal(b, &e); err != nil {
			return nil, err
		}
		p.infoElems = append(p.infoElems, e)
	}
	if len(p.infoElems) <= csrSPKIIndex {
		return nil, errors.New("brainpool: certification request info too short")
	}
	return p, nil
}

func (p *csrParts) infoWithSPKI(spki []byte) ([]byte, error) {
	var content []byte
	for i, e := range p.infoElems {
		if i == csrSPKIIndex {
			content = append(content, spki...)
		} else {
			content = append(content, e.FullBytes...)
		}
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: content})
}

// CreateCertificateRequest is x509.CreateCertificateRequest for a brainpool
// signer; any other signer goes to crypto/x509 unchanged. The request is
// signed with ECDSA and SHA-256, SHA-384 or SHA-512 for 256-, 384- and
// 512-bit keys unless template.SignatureAlgorithm names another ECDSA
// algorithm.
func CreateCertificateRequest(rand io.Reader, template *x509.CertificateRequest, signer crypto.Signer) ([]byte, error) {
	if template == nil || signer == nil {
		return nil, errors.New("brainpool: nil template or signer")
	}
	if rand == nil {
		rand = crand.Reader
	}
	bp, ok := brainpoolPublic(signer.Public())
	if !ok {
		return x509.CreateCertificateRequest(rand, template, signer)
	}
	tmpl := *template
	switch tmpl.SignatureAlgorithm {
	case x509.UnknownSignatureAlgorithm:
		tmpl.SignatureAlgorithm = sigAlgForBrainpool(bp)
	case x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
	default:
		return nil, fmt.Errorf("brainpool: signature algorithm %v cannot be used with a brainpool key", tmpl.SignatureAlgorithm)
	}
	placeholder, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, err
	}
	tmpDER, err := x509.CreateCertificateRequest(rand, &tmpl, placeholder)
	if err != nil {
		return nil, err
	}
	parts, err := splitCSR(tmpDER)
	if err != nil {
		return nil, err
	}
	spki, err := MarshalPKIXPublicKey(bp)
	if err != nil {
		return nil, err
	}
	info, err := parts.infoWithSPKI(spki)
	if err != nil {
		return nil, err
	}
	sig, err := signTBS(rand, signer, tmpl.SignatureAlgorithm, info)
	if err != nil {
		return nil, err
	}
	sigValue, err := asn1.Marshal(asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)})
	if err != nil {
		return nil, err
	}
	der, err := assembleCertificate(info, parts.sigAlg.FullBytes, sigValue)
	if err != nil {
		return nil, err
	}
	if _, err := ParseCertificateRequest(der); err != nil {
		return nil, fmt.Errorf("brainpool: the request does not verify: %w", err)
	}
	return der, nil
}

// ParseCertificateRequest parses a DER certification request and checks
// its signature. Requests crypto/x509 accepts are returned as it parses
// them. For a brainpool subject key, Raw, RawTBSCertificateRequest and
// RawSubjectPublicKeyInfo are the original bytes and PublicKey is the
// brainpool *ecdsa.PublicKey.
func ParseCertificateRequest(der []byte) (*x509.CertificateRequest, error) {
	req, err := x509.ParseCertificateRequest(der)
	if err == nil {
		if err := req.CheckSignature(); err != nil {
			return nil, err
		}
		return req, nil
	}
	p, perr := splitCSR(der)
	if perr != nil {
		return nil, err
	}
	spki := p.infoElems[csrSPKIIndex].FullBytes
	pub, perr := ParsePKIXPublicKey(spki)
	if perr != nil {
		return nil, err // not a brainpool key: report crypto/x509's error
	}
	info, perr := p.infoWithSPKI(placeholderSPKI)
	if perr != nil {
		return nil, perr
	}
	patched, perr := assembleCertificate(info, p.sigAlg.FullBytes, p.sigValue.FullBytes)
	if perr != nil {
		return nil, perr
	}
	req, err = x509.ParseCertificateRequest(patched)
	if err != nil {
		return nil, err
	}
	h, ok := map[x509.SignatureAlgorithm]crypto.Hash{
		x509.ECDSAWithSHA256: crypto.SHA256, x509.ECDSAWithSHA384: crypto.SHA384, x509.ECDSAWithSHA512: crypto.SHA512,
	}[req.SignatureAlgorithm]
	if !ok {
		return nil, fmt.Errorf("brainpool: signature algorithm %v cannot be used with a brainpool key", req.SignatureAlgorithm)
	}
	hh := h.New()
	hh.Write(p.infoFull)
	if !Verify(pub, hh.Sum(nil), req.Signature) {
		return nil, errors.New("brainpool: the certification request signature does not verify")
	}
	req.Raw = append([]byte(nil), der...)
	req.RawTBSCertificateRequest = append([]byte(nil), p.infoFull...)
	req.RawSubjectPublicKeyInfo = append([]byte(nil), spki...)
	req.PublicKey = pub
	req.PublicKeyAlgorithm = x509.ECDSA
	return req, nil
}

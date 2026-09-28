// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"crypto/x509"
	"errors"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// scope is what a CRL covers, from its issuing distribution point
// extension (RFC 5280 5.2.5). The zero scope covers every certificate of
// the issuer.
type scope struct {
	uris     []string // distribution point URIs; empty means any
	onlyUser bool     // end-entity certificates only
	onlyCA   bool     // CA certificates only
}

func (sc scope) covers(cert *x509.Certificate) bool {
	isCA := cert.BasicConstraintsValid && cert.IsCA
	if sc.onlyUser && isCA || sc.onlyCA && !isCA {
		return false
	}
	if len(sc.uris) == 0 {
		return true
	}
	// A partitioned CRL covers the certificates that name one of its
	// distribution points. A certificate without CRL distribution
	// points is not covered.
	for _, u := range cert.CRLDistributionPoints {
		if slices.Contains(sc.uris, u) {
			return true
		}
	}
	return false
}

var errMalformedIDP = errors.New("malformed issuing distribution point extension")

// parseIDP reads the issuing distribution point extension. The fields
// are implicitly tagged. Scopes tlsx cannot apply correctly (reason
// partitions, indirect CRLs, attribute certificates, names relative to
// the issuer or non-URI names) make the CRL unusable.
func parseIDP(der []byte) (scope, error) {
	var sc scope
	in := cryptobyte.String(der)
	var seq cryptobyte.String
	if !in.ReadASN1(&seq, cbasn1.SEQUENCE) || !in.Empty() {
		return sc, errMalformedIDP
	}

	var dpn cryptobyte.String
	var hasDPN bool
	if !seq.ReadOptionalASN1(&dpn, &hasDPN, cbasn1.Tag(0).Constructed().ContextSpecific()) {
		return sc, errMalformedIDP
	}
	if hasDPN {
		var names cryptobyte.String
		var hasFull bool
		if !dpn.ReadOptionalASN1(&names, &hasFull, cbasn1.Tag(0).Constructed().ContextSpecific()) {
			return sc, errMalformedIDP
		}
		if !hasFull || !dpn.Empty() {
			return sc, errors.New("issuing distribution point names relative to the issuer are not supported")
		}
		uriTag := cbasn1.Tag(6).ContextSpecific()
		for !names.Empty() {
			var name cryptobyte.String
			var tag cbasn1.Tag
			if !names.ReadAnyASN1(&name, &tag) {
				return sc, errMalformedIDP
			}
			if tag == uriTag {
				sc.uris = append(sc.uris, string(name))
			}
		}
		if len(sc.uris) == 0 {
			return sc, errors.New("issuing distribution point without a URI is not supported")
		}
	}

	flag := func(n uint8) (bool, error) {
		var v cryptobyte.String
		var present bool
		if !seq.ReadOptionalASN1(&v, &present, cbasn1.Tag(n).ContextSpecific()) {
			return false, errMalformedIDP
		}
		if !present {
			return false, nil
		}
		if len(v) != 1 || (v[0] != 0 && v[0] != 0xff) {
			return false, errMalformedIDP
		}
		return v[0] == 0xff, nil
	}
	var err error
	if sc.onlyUser, err = flag(1); err != nil {
		return sc, err
	}
	if sc.onlyCA, err = flag(2); err != nil {
		return sc, err
	}
	if seq.PeekASN1Tag(cbasn1.Tag(3).ContextSpecific()) {
		return sc, errors.New("CRLs partitioned by reason (onlySomeReasons) are not supported")
	}
	indirect, err := flag(4)
	if err != nil {
		return sc, err
	}
	if indirect {
		return sc, errors.New("indirect CRLs are not supported")
	}
	attrOnly, err := flag(5)
	if err != nil {
		return sc, err
	}
	if attrOnly {
		return sc, errors.New("CRL covers attribute certificates only")
	}
	if !seq.Empty() || sc.onlyUser && sc.onlyCA {
		return sc, errMalformedIDP
	}
	return sc, nil
}

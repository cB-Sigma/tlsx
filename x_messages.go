// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// Wire formats of the extensions tlsx adds to ClientHello, ServerHello
// and CertificateStatus.

const statusTypeOCSPMulti uint8 = 2 // RFC 6961 2.2

// clientHelloExt are the tlsx extensions of a ClientHello.
type clientHelloExt struct {
	encryptThenMAC         bool   // RFC 7366
	maxFragmentLength      uint8  // RFC 6066 4 (1 to 4)
	statusRequestV2        bool   // RFC 6961 (ocsp_multi and ocsp items)
	trustedCAKeys          []byte // RFC 6066 6: the TrustedAuthorities list body
	hasTrustedCAKeys       bool
	certificateAuthorities [][]byte // RFC 8446 4.2.4
	clientAuthz            []uint8  // RFC 5878: formats the client can send
	serverAuthz            []uint8  // RFC 5878: formats the client accepts
	clientCertTypes        []uint8  // RFC 7250 (nil: not sent)
	serverCertTypes        []uint8
}

func (x clientHelloExt) clone() clientHelloExt {
	x.trustedCAKeys = slices.Clone(x.trustedCAKeys)
	x.certificateAuthorities = slices.Clone(x.certificateAuthorities)
	x.clientAuthz, x.serverAuthz = slices.Clone(x.clientAuthz), slices.Clone(x.serverAuthz)
	x.clientCertTypes, x.serverCertTypes = slices.Clone(x.clientCertTypes), slices.Clone(x.serverCertTypes)
	return x
}

func (x *clientHelloExt) marshal(b *cryptobyte.Builder, echInner bool) {
	if echInner {
		return
	}
	if x.maxFragmentLength != 0 {
		b.AddUint16(extensionMaxFragmentLength)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(x.maxFragmentLength) })
	}
	if x.hasTrustedCAKeys {
		b.AddUint16(extensionTrustedCAKeys)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(x.trustedCAKeys) })
		})
	}
	if x.statusRequestV2 {
		// CertificateStatusRequestListV2 with an ocsp_multi and an ocsp item,
		// each with empty responder_id_list and request_extensions.
		b.AddUint16(extensionStatusRequestV2)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, t := range []uint8{statusTypeOCSPMulti, statusTypeOCSP} {
					b.AddUint8(t)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						b.AddUint16(0)
						b.AddUint16(0)
					})
				}
			})
		})
	}
	if x.encryptThenMAC {
		b.AddUint16(extensionEncryptThenMAC)
		b.AddUint16(0)
	}
	if x.clientAuthz != nil {
		addAuthzFormats(b, extensionClientAuthz, x.clientAuthz)
	}
	if x.serverAuthz != nil {
		addAuthzFormats(b, extensionServerAuthz, x.serverAuthz)
	}
	if x.clientCertTypes != nil {
		addCertTypeList(b, extensionClientCertificateType, x.clientCertTypes)
	}
	if x.serverCertTypes != nil {
		addCertTypeList(b, extensionServerCertificateType, x.serverCertTypes)
	}
	// Adapted from Go's crypto/tls/handshake_messages.go:
	// certificateRequestMsgTLS13.marshal (certificate_authorities).
	// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
	if len(x.certificateAuthorities) > 0 {
		b.AddUint16(extensionCertificateAuthorities)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				for _, ca := range x.certificateAuthorities {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ca) })
				}
			})
		})
	}
}

// unmarshal reads one extension; handled says it was one of ours, ok that
// it parsed (the caller checks that extData is consumed).
func (x *clientHelloExt) unmarshal(ext uint16, d *cryptobyte.String) (handled, ok bool) {
	switch ext {
	case extensionMaxFragmentLength:
		return true, d.ReadUint8(&x.maxFragmentLength) && x.maxFragmentLength >= 1 && x.maxFragmentLength <= 4
	case extensionTrustedCAKeys:
		var list cryptobyte.String
		if !d.ReadUint16LengthPrefixed(&list) {
			return true, false
		}
		x.hasTrustedCAKeys = true
		x.trustedCAKeys = slices.Clone([]byte(list))
		_, err := parseTrustedAuthorities(x.trustedCAKeys)
		return true, err == nil
	case extensionStatusRequestV2:
		var list cryptobyte.String
		if !d.ReadUint16LengthPrefixed(&list) {
			return true, false
		}
		for !list.Empty() {
			var t uint8
			var req cryptobyte.String
			if !list.ReadUint8(&t) || !list.ReadUint16LengthPrefixed(&req) {
				return true, false
			}
			if t == statusTypeOCSPMulti || t == statusTypeOCSP {
				x.statusRequestV2 = true
			}
		}
		return true, true
	case extensionEncryptThenMAC:
		x.encryptThenMAC = true
		return true, true
	case extensionClientAuthz:
		return true, readAuthzFormats(d, &x.clientAuthz)
	case extensionServerAuthz:
		return true, readAuthzFormats(d, &x.serverAuthz)
	case extensionClientCertificateType:
		return true, readCertTypeList(d, &x.clientCertTypes)
	case extensionServerCertificateType:
		return true, readCertTypeList(d, &x.serverCertTypes)
	// Adapted from Go's crypto/tls/handshake_messages.go:
	// certificateRequestMsgTLS13.unmarshal (certificate_authorities).
	// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
	case extensionCertificateAuthorities:
		var list cryptobyte.String
		if !d.ReadUint16LengthPrefixed(&list) || list.Empty() {
			return true, false
		}
		for !list.Empty() {
			var dn []byte
			if !readUint16LengthPrefixed(&list, &dn) || len(dn) == 0 {
				return true, false
			}
			x.certificateAuthorities = append(x.certificateAuthorities, dn)
		}
		return true, true
	}
	return false, false
}

// serverHelloExt are the tlsx extensions of a ServerHello (TLS 1.2).
type serverHelloExt struct {
	encryptThenMAC    bool
	maxFragmentLength uint8
	statusRequestV2   bool
	trustedCAKeys     bool
	clientAuthz       []uint8 // RFC 5878: the format chosen for each
	serverAuthz       []uint8
	certTypes         certTypeAnswer // RFC 7250
}

func (x *serverHelloExt) marshal(b *cryptobyte.Builder) {
	if x.maxFragmentLength != 0 {
		b.AddUint16(extensionMaxFragmentLength)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(x.maxFragmentLength) })
	}
	if x.trustedCAKeys {
		b.AddUint16(extensionTrustedCAKeys)
		b.AddUint16(0)
	}
	if x.statusRequestV2 {
		b.AddUint16(extensionStatusRequestV2)
		b.AddUint16(0)
	}
	if x.encryptThenMAC {
		b.AddUint16(extensionEncryptThenMAC)
		b.AddUint16(0)
	}
	if x.clientAuthz != nil {
		addAuthzFormats(b, extensionClientAuthz, x.clientAuthz)
	}
	if x.serverAuthz != nil {
		addAuthzFormats(b, extensionServerAuthz, x.serverAuthz)
	}
	x.certTypes.marshal(b)
}

func (x *serverHelloExt) unmarshal(ext uint16, d *cryptobyte.String) (handled, ok bool) {
	switch ext {
	case extensionMaxFragmentLength:
		return true, d.ReadUint8(&x.maxFragmentLength) && x.maxFragmentLength >= 1 && x.maxFragmentLength <= 4
	case extensionTrustedCAKeys:
		x.trustedCAKeys = true
		return true, d.Empty()
	case extensionStatusRequestV2:
		x.statusRequestV2 = true
		return true, d.Empty()
	case extensionEncryptThenMAC:
		x.encryptThenMAC = true
		return true, d.Empty()
	case extensionClientAuthz:
		return true, readAuthzFormats(d, &x.clientAuthz)
	case extensionServerAuthz:
		return true, readAuthzFormats(d, &x.serverAuthz)
	}
	return x.certTypes.unmarshal(ext, d)
}

// The marshal and unmarshal methods below are adapted from Go's
// crypto/tls/handshake_messages.go: certificateStatusMsg.marshal and unmarshal.
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// certificateStatusExt is the ocsp_multi form of CertificateStatus: one
// OCSP response per certificate of the chain, empty where there is none.
type certificateStatusExt struct {
	multi     bool
	responses [][]byte
}

func (x *certificateStatusExt) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificateStatus)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(statusTypeOCSPMulti)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, r := range x.responses {
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(r) })
			}
		})
	})
	return b.Bytes()
}

func (x *certificateStatusExt) unmarshal(data []byte, leaf *[]byte) bool {
	s := cryptobyte.String(data)
	var t uint8
	var list cryptobyte.String
	if !s.Skip(4) || !s.ReadUint8(&t) || t != statusTypeOCSPMulti ||
		!s.ReadUint24LengthPrefixed(&list) || !s.Empty() || list.Empty() {
		return false
	}
	x.multi = true
	for !list.Empty() {
		var r []byte
		if !readUint24LengthPrefixed(&list, &r) {
			return false
		}
		if len(r) == 0 {
			r = nil
		}
		x.responses = append(x.responses, r)
	}
	if len(x.responses) > 0 {
		*leaf = x.responses[0]
	}
	return true
}

// parseTrustedAuthorities reads a TrustedAuthorities list body.
func parseTrustedAuthorities(b []byte) ([]TrustedAuthority, error) {
	s := cryptobyte.String(b)
	var out []TrustedAuthority
	for !s.Empty() {
		var t TrustedAuthority
		if !s.ReadUint8(&t.Type) {
			return nil, errTrustedAuthorities
		}
		switch t.Type {
		case TrustedPreAgreed:
		case TrustedKeySHA1Hash, TrustedCertSHA1Hash:
			if !s.ReadBytes(&t.Data, 20) {
				return nil, errTrustedAuthorities
			}
		case TrustedX509Name:
			if !readUint16LengthPrefixed(&s, &t.Data) || len(t.Data) == 0 {
				return nil, errTrustedAuthorities
			}
		default:
			return nil, errTrustedAuthorities
		}
		out = append(out, t)
	}
	return out, nil
}

// marshalTrustedAuthorities writes a TrustedAuthorities list body.
func marshalTrustedAuthorities(l []TrustedAuthority) ([]byte, error) {
	var b cryptobyte.Builder
	for _, t := range l {
		b.AddUint8(t.Type)
		switch t.Type {
		case TrustedPreAgreed:
		case TrustedKeySHA1Hash, TrustedCertSHA1Hash:
			if len(t.Data) != 20 {
				return nil, errTrustedAuthorities
			}
			b.AddBytes(t.Data)
		case TrustedX509Name:
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(t.Data) })
		default:
			return nil, errTrustedAuthorities
		}
	}
	return b.Bytes()
}

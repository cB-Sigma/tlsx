// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"errors"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// TLS authorization extensions (RFC 5878) with the SupplementalData
// handshake message (RFC 4680), TLS 1.2 only, for X.509 attribute
// certificates (IEC 62351-8 11.1, Profile B tokens).
//
// A client lists in client_authz the formats it can send and in
// server_authz the formats it accepts; a server answers each with the
// formats it chose. When server_authz is agreed the server sends a
// SupplementalData message right after ServerHello; when client_authz is
// agreed the client sends one after ServerHelloDone, before its
// Certificate. Neither is sent on an abbreviated (resumed) handshake.

const (
	extensionClientAuthz uint16 = 7 // RFC 5878 3.1
	extensionServerAuthz uint16 = 8 // RFC 5878 3.2

	typeSupplementalData uint8 = 23 // RFC 4680 2

	supplementalAuthzData uint16 = 16386 // RFC 5878 3.3: authz_data

	// AuthzX509AttrCert is the x509_attr_cert authorization data format.
	AuthzX509AttrCert uint8 = 0
)

var errAuthz = errors.New("tlsx: malformed authorization data")

// authzFormats reads an AuthzDataFormats list (1 to 255 formats).
func readAuthzFormats(d *cryptobyte.String, out *[]uint8) bool {
	var list cryptobyte.String
	if !d.ReadUint8LengthPrefixed(&list) || list.Empty() {
		return false
	}
	*out = slices.Clone([]uint8(list))
	return true
}

func addAuthzFormats(b *cryptobyte.Builder, ext uint16, f []uint8) {
	b.AddUint16(ext)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(f) })
	})
}

// supplementalDataMsg is a SupplementalData message whose authz_data
// entry carries attribute certificates.
type supplementalDataMsg struct {
	attrCerts [][]byte
}

func (m *supplementalDataMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeSupplementalData)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(supplementalAuthzData)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, ac := range m.attrCerts {
						b.AddUint8(AuthzX509AttrCert)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ac) })
					}
				})
			})
		})
	})
	return b.Bytes()
}

func (m *supplementalDataMsg) unmarshal(data []byte) bool {
	*m = supplementalDataMsg{}
	s := cryptobyte.String(data)
	var entries cryptobyte.String
	if !s.Skip(4) || !s.ReadUint24LengthPrefixed(&entries) || !s.Empty() || entries.Empty() {
		return false
	}
	for !entries.Empty() {
		var typ uint16
		var body cryptobyte.String
		if !entries.ReadUint16(&typ) || !entries.ReadUint16LengthPrefixed(&body) {
			return false
		}
		if typ != supplementalAuthzData {
			continue // an entry type we do not know is skipped
		}
		var list cryptobyte.String
		if !body.ReadUint16LengthPrefixed(&list) || !body.Empty() || list.Empty() {
			return false
		}
		for !list.Empty() {
			var f uint8
			if !list.ReadUint8(&f) || f != AuthzX509AttrCert {
				return false // only x509_attr_cert is agreed
			}
			var ac []byte
			if !readUint16LengthPrefixed(&list, &ac) || len(ac) == 0 {
				return false
			}
			m.attrCerts = append(m.attrCerts, ac)
		}
	}
	return true
}

// clientAuthzOffer fills the ClientHello's authorization extensions (TLS
// 1.2 only: TLS 1.3 has no SupplementalData).
func (c *Conn) clientAuthzOffer(hello *clientHelloMsg, minVersion uint16) {
	x := &c.config.Ext
	if minVersion > VersionTLS12 {
		return
	}
	if len(x.AttributeCertificates) > 0 {
		hello.x.clientAuthz = []uint8{AuthzX509AttrCert}
	}
	if x.AcceptAttributeCertificates {
		hello.x.serverAuthz = []uint8{AuthzX509AttrCert}
	}
}

// clientAuthzAnswer checks the server's answer: only formats offered.
func (c *Conn) clientAuthzAnswer(hs *clientHandshakeState) error {
	sh, ch := &hs.serverHello.x, &hs.hello.x
	for _, p := range []struct{ got, offered []uint8 }{{sh.clientAuthz, ch.clientAuthz}, {sh.serverAuthz, ch.serverAuthz}} {
		if p.got == nil {
			continue
		}
		if p.offered == nil || len(p.got) != 1 || !slices.Contains(p.offered, p.got[0]) {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tlsx: server answered an authorization format that was not offered")
		}
	}
	return nil
}

// serverAuthzAnswer chooses the formats of a TLS 1.2 full handshake.
func (hs *serverHandshakeState) serverAuthzAnswer() {
	c, ch := hs.c, &hs.clientHello.x
	x := &c.config.Ext
	if hs.sessionState != nil {
		return
	}
	if x.AcceptAttributeCertificates && slices.Contains(ch.clientAuthz, AuthzX509AttrCert) {
		hs.hello.x.clientAuthz = []uint8{AuthzX509AttrCert}
	}
	if len(x.AttributeCertificates) > 0 && slices.Contains(ch.serverAuthz, AuthzX509AttrCert) {
		hs.hello.x.serverAuthz = []uint8{AuthzX509AttrCert}
	}
}

// readPeerSupplemental reads the peer's SupplementalData when it was
// agreed; msg is the next handshake message, and the one after the
// SupplementalData is returned.
func (c *Conn) readPeerSupplemental(agreed bool, msg any, next func() (any, error)) (any, error) {
	if !agreed {
		return msg, nil
	}
	sd, ok := msg.(*supplementalDataMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, errors.New("tlsx: SupplementalData with the attribute certificates expected")
	}
	c.x.peerAttrCerts = sd.attrCerts
	return next()
}

// sendSupplemental sends our SupplementalData when it was agreed.
func (c *Conn) sendSupplemental(agreed bool, transcript transcriptHash) error {
	if !agreed {
		return nil
	}
	_, err := c.writeHandshakeRecord(&supplementalDataMsg{attrCerts: c.config.Ext.AttributeCertificates}, transcript)
	return err
}

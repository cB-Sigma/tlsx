// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"slices"
)

var errTrustedAuthorities = errors.New("tlsx: malformed trusted_ca_keys")

// ---- client ------------------------------------------------------------------

// clientHelloExtensions adds the tlsx extensions to a ClientHello.
func (c *Conn) clientHelloExtensions(hello *clientHelloMsg, maxVersion, minVersion uint16) error {
	x := &c.config.Ext
	tls12 := minVersion <= VersionTLS12
	if !x.PSK.clientReady() { // PSK suites need a PSK
		hello.cipherSuites = slices.DeleteFunc(hello.cipherSuites, IsPSKSuite)
	}
	c.clientCertTypeOffer(hello)
	if tls12 && (x.EncryptThenMAC || x.RequireEncryptThenMAC) && slices.ContainsFunc(hello.cipherSuites, func(id uint16) bool {
		return isCBCSuite(cipherSuiteByID(id))
	}) {
		hello.x.encryptThenMAC = true
	}
	if m := x.MaxFragmentLength; m != 0 {
		if m > 4 {
			return errors.New("tlsx: MaxFragmentLength must be 1 to 4")
		}
		hello.x.maxFragmentLength = m
	}
	if tls12 && x.RequestOCSPMulti {
		hello.x.statusRequestV2 = true
	}
	if len(x.TrustedCAKeys) > 0 {
		b, err := marshalTrustedAuthorities(x.TrustedCAKeys)
		if err != nil {
			return err
		}
		hello.x.trustedCAKeys, hello.x.hasTrustedCAKeys = b, true
	}
	if maxVersion >= VersionTLS13 && len(x.CertificateAuthorities) > 0 {
		hello.x.certificateAuthorities = x.CertificateAuthorities
	}
	c.clientAuthzOffer(hello, minVersion)
	if maxVersion >= VersionTLS13 && len(x.CipherSuitesTLS13) > 0 {
		hello.cipherSuites = slices.DeleteFunc(hello.cipherSuites, func(id uint16) bool { return cipherSuiteTLS13ByID(id) != nil })
		hello.cipherSuites = append(hello.cipherSuites, x.CipherSuitesTLS13...)
	}
	return nil
}

// processServerHelloExtensions checks the tlsx extensions of a TLS 1.2
// ServerHello.
func (c *Conn) processServerHelloExtensions(hs *clientHandshakeState) error {
	sh, ch := &hs.serverHello.x, &hs.hello.x
	if sh.encryptThenMAC {
		if !ch.encryptThenMAC || !isCBCSuite(hs.suite) {
			c.sendAlert(alertUnsupportedExtension)
			return errors.New("tlsx: server sent encrypt_then_mac without a CBC suite or unasked")
		}
		hs.etm = true
	}
	if isCBCSuite(hs.suite) && !hs.etm {
		if c.config.Ext.RequireEncryptThenMAC {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tlsx: server selected a CBC cipher suite without encrypt_then_mac")
		}
		if c.handshakes > 0 && c.in.etm { // RFC 7366 3.1: no downgrade on renegotiation
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tlsx: renegotiation dropped encrypt_then_mac")
		}
	}
	if m := sh.maxFragmentLength; m != 0 {
		if m != ch.maxFragmentLength {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tlsx: server answered a different max_fragment_length")
		}
		c.x.maxFragment = 1 << (8 + int(m))
	}
	if sh.statusRequestV2 && !ch.statusRequestV2 || sh.trustedCAKeys && !ch.hasTrustedCAKeys {
		c.sendAlert(alertUnsupportedExtension)
		return errors.New("tlsx: server sent an extension that was not offered")
	}
	c.x.trustedCAAck = sh.trustedCAKeys
	if hs.suite.flags&suitePSK == 0 {
		if err := c.acceptCertTypes(hs.hello, sh.certTypes); err != nil {
			return err
		}
	}
	return c.clientAuthzAnswer(hs)
}

// ---- server ------------------------------------------------------------------

// serverHandshakeExt is the tlsx state of a TLS 1.2 server handshake.
type serverHandshakeExt struct {
	etm bool
}

// serverHelloExtensions answers the tlsx extensions of a ClientHello in
// the TLS 1.2 ServerHello, once the suite (and resumption) is decided.
func (hs *serverHandshakeState) serverHelloExtensions() error {
	c, ch := hs.c, &hs.clientHello.x
	x := &c.config.Ext
	if isCBCSuite(hs.suite) {
		if ch.encryptThenMAC && (x.EncryptThenMAC || x.RequireEncryptThenMAC) {
			hs.hello.x.encryptThenMAC, hs.x.etm = true, true
		} else if x.RequireEncryptThenMAC {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tlsx: CBC cipher suite without encrypt_then_mac")
		} else if c.handshakes > 0 && c.in.etm {
			c.sendAlert(alertHandshakeFailure)
			return errors.New("tlsx: renegotiation dropped encrypt_then_mac")
		}
	}
	if m := ch.maxFragmentLength; m != 0 {
		hs.hello.x.maxFragmentLength = m
		c.x.maxFragment = 1 << (8 + int(m))
	}
	if hs.sessionState == nil {
		if ch.statusRequestV2 && hasStaples(hs.cert.ChainOCSPStaples) {
			hs.hello.x.statusRequestV2 = true
			hs.hello.ocspStapling = false // one CertificateStatus: ocsp_multi
		}
		if x.ServerSessionCache != nil {
			hs.hello.sessionId = make([]byte, 32)
			if _, err := io.ReadFull(c.config.rand(), hs.hello.sessionId); err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
		}
	}
	if ch.hasTrustedCAKeys {
		if l, err := parseTrustedAuthorities(ch.trustedCAKeys); err == nil && TrustedAuthoritiesMatch(hs.cert.Certificate, l) {
			hs.hello.x.trustedCAKeys = true
		}
	}
	hs.serverAuthzAnswer()
	return hs.serverRawKeyExtensions()
}

// certificateStatusV2 turns CertificateStatus into ocsp_multi when that
// was negotiated.
func (hs *serverHandshakeState) certificateStatusV2(m *certificateStatusMsg) {
	if !hs.hello.x.statusRequestV2 {
		return
	}
	m.x.multi = true
	m.x.responses = make([][]byte, len(hs.cert.Certificate))
	m.x.responses[0] = hs.cert.OCSPStaple
	for i, r := range hs.cert.ChainOCSPStaples {
		if i+1 < len(m.x.responses) {
			m.x.responses[i+1] = r
		}
	}
}

// sessionFromID looks the ClientHello's session ID up in the server
// session cache (no ticket offered).
func (hs *serverHandshakeState) sessionFromID() *SessionState {
	cache := hs.c.config.Ext.ServerSessionCache
	if cache == nil || len(hs.clientHello.sessionTicket) > 0 || len(hs.clientHello.sessionId) == 0 {
		return nil
	}
	ss, ok := cache.Get(string(hs.clientHello.sessionId))
	if !ok || ss == nil {
		return nil
	}
	return ss
}

// saveSessionID stores a full handshake's session under the session ID
// the ServerHello gave it.
func (hs *serverHandshakeState) saveSessionID() {
	cache := hs.c.config.Ext.ServerSessionCache
	if cache == nil || len(hs.hello.sessionId) == 0 || hs.c.x.noSessionCache() {
		return
	}
	state := hs.c.sessionState()
	state.secret = hs.masterSecret
	cache.Put(string(hs.hello.sessionId), state)
}

// helloExt fills ClientHelloInfo.Ext.
func helloExt(c *Conn, ch *clientHelloMsg) HelloExt {
	h := HelloExt{
		PSKModes:               ch.pskModes,
		CertificateAuthorities: ch.x.certificateAuthorities,
		EncryptThenMAC:         ch.x.encryptThenMAC,
		MaxFragmentLength:      ch.x.maxFragmentLength,
		StatusRequestV2:        ch.x.statusRequestV2,
		SecureRenegotiation:    ch.secureRenegotiationSupported,
		Renegotiation:          c.handshakes > 0,
	}
	if ch.x.hasTrustedCAKeys {
		h.TrustedCAKeys, _ = parseTrustedAuthorities(ch.x.trustedCAKeys)
		if h.TrustedCAKeys == nil {
			h.TrustedCAKeys = []TrustedAuthority{}
		}
	}
	return h
}

// ---- signature algorithm lists ----------------------------------------------

// sigAlgsX is the signature_algorithms list for version: the configured
// one (Config.Ext.SignatureSchemes) or def, with the SHA-1 schemes when
// Config.Ext.AllowSHA1Signatures allows them (x_sha1.go).
func (c *Config) sigAlgsX(def []SignatureScheme, version uint16) []SignatureScheme {
	if c == nil {
		return def
	}
	if len(c.Ext.SignatureSchemes) == 0 {
		return c.sigAlgsSHA1X(def, version)
	}
	return c.sigAlgsSHA1X(slices.DeleteFunc(slices.Clone(c.Ext.SignatureSchemes), func(s SignatureScheme) bool {
		return isDisabledSignatureAlgorithm(version, s, false)
	}), version)
}

// sigAlgsCertX adds the configured schemes to signature_algorithms_cert.
func (c *Config) sigAlgsCertX(def []SignatureScheme) []SignatureScheme {
	if c == nil {
		return def
	}
	for _, s := range c.Ext.SignatureSchemes {
		if !slices.Contains(def, s) {
			def = append(def, s)
		}
	}
	return def
}

// ---- trusted CA indication (RFC 6066 6) -------------------------------------

// TrustedAuthoritiesFor lists the trusted_ca_keys entries that name the
// CA certificates given (DER): key_sha1_hash and x509_name of each.
func TrustedAuthoritiesFor(cas [][]byte) ([]TrustedAuthority, error) {
	var out []TrustedAuthority
	for _, der := range cas {
		cert, err := parseCertificateX(der)
		if err != nil {
			return nil, err
		}
		h, err := keySHA1(cert)
		if err != nil {
			return nil, err
		}
		out = append(out, TrustedAuthority{Type: TrustedKeySHA1Hash, Data: h},
			TrustedAuthority{Type: TrustedX509Name, Data: cert.RawSubject})
	}
	return out, nil
}

// keySHA1 is the SHA-1 hash of a certificate's subjectPublicKey bits.
func keySHA1(cert *x509.Certificate) ([]byte, error) {
	var s spki
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &s); err != nil {
		return nil, err
	}
	h := sha1.Sum(s.PublicKey.RightAlign())
	return h[:], nil
}

// TrustedAuthoritiesMatch reports whether the certificate chain (DER,
// leaf first) chains to an authority of the list: a pre_agreed entry, the
// SHA-1 of a chain certificate, the name of an issuer in the chain, or the
// key hash of a chain CA or of an issuer named by an authority key
// identifier.
func TrustedAuthoritiesMatch(chain [][]byte, list []TrustedAuthority) bool {
	var certs []*x509.Certificate
	for _, der := range chain {
		c, err := parseCertificateX(der)
		if err != nil {
			return false
		}
		certs = append(certs, c)
	}
	for _, t := range list {
		switch t.Type {
		case TrustedPreAgreed:
			return true
		case TrustedCertSHA1Hash:
			for _, der := range chain {
				if h := sha1.Sum(der); bytes.Equal(h[:], t.Data) {
					return true
				}
			}
		case TrustedX509Name:
			for _, c := range certs {
				if bytes.Equal(c.RawIssuer, t.Data) {
					return true
				}
			}
		case TrustedKeySHA1Hash:
			for i, c := range certs {
				if bytes.Equal(c.AuthorityKeyId, t.Data) {
					return true
				}
				if i > 0 {
					if h, err := keySHA1(c); err == nil && bytes.Equal(h, t.Data) {
						return true
					}
				}
			}
		}
	}
	return false
}

// saveSessionID caches a TLS 1.2 session the server gave a session ID and
// no ticket (Config.Ext.ClientSessionIDs). Its caching steps are adapted
// from Go's saveSessionTicket in src/crypto/tls/handshake_client.go
// (Copyright 2009 The Go Authors; see NOTICE).
func (hs *clientHandshakeState) saveSessionID() error {
	c := hs.c
	if !c.config.Ext.ClientSessionIDs || c.config.ClientSessionCache == nil || c.didResume || c.x.noSessionCache() ||
		len(hs.serverHello.sessionId) == 0 || bytes.Equal(hs.serverHello.sessionId, hs.hello.sessionId) {
		return nil
	}
	cacheKey := c.clientSessionCacheKey()
	if cacheKey == "" {
		return nil
	}
	session := c.sessionState()
	session.secret = hs.masterSecret
	c.config.ClientSessionCache.Put(cacheKey, &ClientSessionState{session: session, sessionID: slices.Clone(hs.serverHello.sessionId)})
	return nil
}

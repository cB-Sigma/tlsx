// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// Raw public keys (RFC 7250) in TLS 1.2 and 1.3: the
// client_certificate_type and server_certificate_type extensions, and a
// Certificate message that carries a SubjectPublicKeyInfo instead of an
// X.509 chain (TLS 1.2: the SPKI alone, RFC 7250 3; TLS 1.3: one
// CertificateEntry, RFC 8446 4.4.2). A raw key is trusted only through
// RawPublicKeyConfig.Verify (a pinned set of keys, for instance); X.509
// certificates stay accepted and verified as usual unless RawOnly.
//
// With a raw key, ConnectionState().PeerCertificates is empty and
// Ext.PeerRawPublicKey holds the peer's SPKI. Such sessions are neither
// cached nor ticketed.

// Extension and certificate type numbers of RFC 7250.
const (
	extensionClientCertificateType uint16 = 19
	extensionServerCertificateType uint16 = 20

	CertificateTypeX509         uint8 = 0
	CertificateTypeRawPublicKey uint8 = 2
)

// RawPublicKeyConfig configures raw public keys (Config.Ext.RawPublicKeys).
type RawPublicKeyConfig struct {
	// Send authenticates this side with the public key of its certificate's
	// private key as a raw public key when the peer accepts one. The
	// Certificate may then have no X.509 chain (PrivateKey only); with a
	// chain, X.509 remains the choice for a peer that does not accept raw
	// keys.
	Send bool
	// Verify accepts the peer's raw public key (DER SubjectPublicKeyInfo),
	// typically against a pinned set; a nil error accepts it. Nil: raw keys
	// from the peer are not accepted.
	Verify func(spki []byte) error
	// RawOnly refuses X.509 certificates from the peer.
	RawOnly bool
}

// certTypeAnswer is the certificate type extensions of a ServerHello
// (TLS 1.2) or EncryptedExtensions (TLS 1.3): one type each, if sent.
type certTypeAnswer struct {
	hasClient, hasServer bool
	client, server       uint8
}

func (a *certTypeAnswer) marshal(b *cryptobyte.Builder) {
	if a.hasClient {
		b.AddUint16(extensionClientCertificateType)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(a.client) })
	}
	if a.hasServer {
		b.AddUint16(extensionServerCertificateType)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(a.server) })
	}
}

func (a *certTypeAnswer) unmarshal(ext uint16, d *cryptobyte.String) (handled, ok bool) {
	switch ext {
	case extensionClientCertificateType:
		a.hasClient = true
		return true, d.ReadUint8(&a.client)
	case extensionServerCertificateType:
		a.hasServer = true
		return true, d.ReadUint8(&a.server)
	}
	return false, false
}

// addCertTypeList writes a ClientHello certificate type extension.
func addCertTypeList(b *cryptobyte.Builder, ext uint16, types []uint8) {
	b.AddUint16(ext)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(types) })
	})
}

func readCertTypeList(d *cryptobyte.String, out *[]uint8) bool {
	var l cryptobyte.String
	if !d.ReadUint8LengthPrefixed(&l) || l.Empty() {
		return false
	}
	*out = slices.Clone([]uint8(l))
	return true
}

// clientCertTypeOffer fills a ClientHello's certificate type lists.
func (c *Conn) clientCertTypeOffer(hello *clientHelloMsg) {
	r := c.config.Ext.RawPublicKeys
	if r == nil {
		return
	}
	if r.Verify != nil {
		hello.x.serverCertTypes = []uint8{CertificateTypeRawPublicKey}
		if !r.RawOnly {
			hello.x.serverCertTypes = append(hello.x.serverCertTypes, CertificateTypeX509)
		}
	}
	if r.Send {
		hello.x.clientCertTypes = []uint8{CertificateTypeRawPublicKey}
		if c.config.GetClientCertificate != nil || len(c.config.Certificates) > 0 && len(c.config.Certificates[0].Certificate) > 0 {
			hello.x.clientCertTypes = append(hello.x.clientCertTypes, CertificateTypeX509)
		}
	}
}

// acceptCertTypes checks a server's certificate type answer (ServerHello
// or EncryptedExtensions) against the offer and records it.
func (c *Conn) acceptCertTypes(hello *clientHelloMsg, a certTypeAnswer) error {
	if a.hasServer {
		if !slices.Contains(hello.x.serverCertTypes, a.server) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tlsx: server chose a server certificate type that was not offered")
		}
		c.x.peerRawKey = a.server == CertificateTypeRawPublicKey
	}
	if a.hasClient {
		if !slices.Contains(hello.x.clientCertTypes, a.client) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tlsx: server chose a client certificate type that was not offered")
		}
		c.x.ownRawKey = a.client == CertificateTypeRawPublicKey
	}
	return nil
}

// serverCertTypes decides a server's certificate type and, when it asks
// for a client certificate, the client's (RFC 7250 4.2), in the client's
// order of preference.
func (c *Conn) serverCertTypes(ch *clientHelloMsg, cert *Certificate, requestClient bool) (certTypeAnswer, error) {
	var a certTypeAnswer
	r := c.config.Ext.RawPublicKeys
	haveX509 := cert != nil && len(cert.Certificate) > 0
	_, canSign := cert.PrivateKey.(crypto.Signer)
	canRaw := r != nil && r.Send && canSign
	if ch.x.serverCertTypes != nil {
		found := false
		for _, t := range ch.x.serverCertTypes {
			if t == CertificateTypeRawPublicKey && canRaw || t == CertificateTypeX509 && haveX509 {
				a.hasServer, a.server, found = true, t, true
				break
			}
		}
		if !found {
			c.sendAlert(alertUnsupportedCertificate)
			return a, errors.New("tlsx: no server certificate type both sides support")
		}
		c.x.ownRawKey = a.server == CertificateTypeRawPublicKey
	} else if !haveX509 {
		c.sendAlert(alertUnsupportedCertificate)
		return a, errors.New("tlsx: the client does not accept raw public keys and this server has no X.509 certificate")
	}
	if requestClient && ch.x.clientCertTypes != nil {
		acceptRaw := r != nil && r.Verify != nil
		acceptX509 := r == nil || !r.RawOnly
		found := false
		for _, t := range ch.x.clientCertTypes {
			if t == CertificateTypeRawPublicKey && acceptRaw || t == CertificateTypeX509 && acceptX509 {
				a.hasClient, a.client, found = true, t, true
				break
			}
		}
		if !found {
			c.sendAlert(alertUnsupportedCertificate)
			return a, errors.New("tlsx: no client certificate type both sides support")
		}
		c.x.peerRawKey = a.client == CertificateTypeRawPublicKey
	}
	return a, nil
}

// rawKeyCertificate is cert with its chain replaced by the SPKI of its
// key, and no staples.
func rawKeyCertificate(cert *Certificate) (*Certificate, error) {
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("tlsx: a raw public key needs a crypto.Signer private key")
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("tlsx: raw public key: %w", err)
	}
	return &Certificate{Certificate: [][]byte{spki}, PrivateKey: cert.PrivateKey,
		SupportedSignatureAlgorithms: cert.SupportedSignatureAlgorithms}, nil
}

// RawPublicKeyCertificate is a Certificate for authenticating with key
// as a raw public key only (RawPublicKeyConfig.Send, no X.509 chain).
func RawPublicKeyCertificate(key crypto.Signer) Certificate {
	return Certificate{PrivateKey: key}
}

// serverRawKeyExtensions answers the certificate type extensions in a
// TLS 1.2 ServerHello (full handshakes with certificate suites).
func (hs *serverHandshakeState) serverRawKeyExtensions() error {
	c := hs.c
	if hs.sessionState != nil || hs.suite == nil || hs.suite.flags&suitePSK != 0 {
		return nil
	}
	a, err := c.serverCertTypes(hs.clientHello, hs.cert, c.config.ClientAuth >= RequestClientCert)
	if err != nil {
		return err
	}
	hs.hello.x.certTypes = a
	if c.x.ownRawKey {
		if hs.cert, err = rawKeyCertificate(hs.cert); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		hs.hello.ocspStapling, hs.hello.scts, hs.hello.x.statusRequestV2 = false, nil, false
	}
	if c.x.noSessionCache() {
		hs.hello.ticketSupported = false
		hs.hello.sessionId = nil
	}
	return nil
}

// serverRawKeyTLS13 answers the certificate type extensions in a TLS 1.3
// EncryptedExtensions and swaps in the raw key.
func (hs *serverHandshakeStateTLS13) serverRawKeyTLS13(ee *encryptedExtensionsMsg) error {
	c := hs.c
	if hs.usingPSK {
		return nil
	}
	a, err := c.serverCertTypes(hs.clientHello, hs.cert, hs.requestClientCert())
	if err != nil {
		return err
	}
	ee.certTypes = a
	if c.x.ownRawKey {
		if hs.cert, err = rawKeyCertificate(hs.cert); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}
	return nil
}

// getClientCertificateX is getClientCertificate, or the raw key when the
// server chose one for the client.
func (c *Conn) getClientCertificateX(cri *CertificateRequestInfo) (*Certificate, error) {
	if !c.x.ownRawKey {
		return c.getClientCertificate(cri)
	}
	var cert *Certificate
	if c.config.GetClientCertificate != nil {
		var err error
		if cert, err = c.config.GetClientCertificate(cri); err != nil {
			return nil, err
		}
	} else if len(c.config.Certificates) > 0 {
		cert = &c.config.Certificates[0]
	}
	if cert == nil {
		return new(Certificate), nil
	}
	if _, ok := cert.PrivateKey.(crypto.Signer); !ok {
		return new(Certificate), nil
	}
	return rawKeyCertificate(cert)
}

// parseRawKey checks a peer's raw public key and gives the stand-in
// certificate the handshake code uses for its signature checks.
func (c *Conn) parseRawKey(spki []byte) (*x509.Certificate, error) {
	r := c.config.Ext.RawPublicKeys
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		c.sendAlert(alertDecodeError)
		return nil, errors.New("tlsx: failed to parse the peer's raw public key: " + err.Error())
	}
	cert := &x509.Certificate{Raw: spki, RawSubjectPublicKeyInfo: spki, PublicKey: pub}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		// Adapted from Go's crypto/tls/handshake_server.go: processCertsFromClient
		// (the RSA key size check). Copyright The Go Authors, BSD-3-Clause; see NOTICE.
		if max, ok := checkKeySize(k.N.BitLen()); !ok {
			c.sendAlert(alertBadCertificate)
			return nil, fmt.Errorf("tlsx: raw public key larger than %d bits", max)
		}
		cert.PublicKeyAlgorithm = x509.RSA
	case *ecdsa.PublicKey:
		cert.PublicKeyAlgorithm = x509.ECDSA
	case ed25519.PublicKey:
		cert.PublicKeyAlgorithm = x509.Ed25519
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return nil, fmt.Errorf("tlsx: unsupported raw public key type %T", pub)
	}
	if r == nil || r.Verify == nil {
		c.sendAlert(alertUnsupportedCertificate)
		return nil, errors.New("tlsx: raw public keys are not accepted")
	}
	if err := r.Verify(spki); err != nil {
		c.sendAlert(alertBadCertificate)
		return nil, fmt.Errorf("tlsx: raw public key refused: %w", err)
	}
	c.x.peerRawKeySPKI = slices.Clone(spki)
	return cert, nil
}

// verifyServerRawKey handles a server's Certificate when a raw key was
// negotiated or X.509 is refused; handled says verifyServerCertificate
// has nothing left to do.
func (c *Conn) verifyServerRawKey(certificates [][]byte) (handled bool, err error) {
	r := c.config.Ext.RawPublicKeys
	if !c.x.peerRawKey {
		if r != nil && r.RawOnly {
			c.sendAlert(alertUnsupportedCertificate)
			return true, errors.New("tlsx: the server sent an X.509 certificate and only raw public keys are accepted")
		}
		return false, nil
	}
	if len(certificates) != 1 {
		c.sendAlert(alertDecodeError)
		return true, errors.New("tlsx: a raw public key Certificate must hold one key")
	}
	cert, err := c.parseRawKey(certificates[0])
	if err != nil {
		return true, err
	}
	// The VerifyConnection step is adapted from Go's crypto/tls/handshake_client.go:
	// verifyServerCertificate. Copyright The Go Authors, BSD-3-Clause; see NOTICE.
	c.peerCertificates = []*x509.Certificate{cert}
	c.verifiedChains = nil
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return true, err
		}
	}
	return true, nil
}

// processClientRawKey is processCertsFromClient for a raw key (or a
// refused X.509 certificate).
func (c *Conn) processClientRawKey(certificates [][]byte) (handled bool, err error) {
	r := c.config.Ext.RawPublicKeys
	if !c.x.peerRawKey {
		if r != nil && r.RawOnly && len(certificates) > 0 {
			c.sendAlert(alertUnsupportedCertificate)
			return true, errors.New("tlsx: the client sent an X.509 certificate and only raw public keys are accepted")
		}
		return false, nil
	}
	// Adapted from Go's crypto/tls/handshake_server.go: processCertsFromClient
	// (the missing-certificate check). Copyright The Go Authors, BSD-3-Clause; see NOTICE.
	if len(certificates) == 0 {
		if requiresClientCert(c.config.ClientAuth) {
			if c.vers == VersionTLS13 {
				c.sendAlert(alertCertificateRequired)
			} else {
				c.sendAlert(alertHandshakeFailure)
			}
			return true, errors.New("tls: client didn't provide a certificate")
		}
		return true, nil
	}
	if len(certificates) != 1 {
		c.sendAlert(alertDecodeError)
		return true, errors.New("tlsx: a raw public key Certificate must hold one key")
	}
	cert, err := c.parseRawKey(certificates[0])
	if err != nil {
		return true, err
	}
	c.peerCertificates = []*x509.Certificate{cert}
	c.verifiedChains = nil
	return true, nil
}

// marshalRawKey and unmarshalRawKey are adapted from Go's
// crypto/tls/handshake_messages.go: certificateMsg.marshal and unmarshal (the
// message framing). Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// TLS 1.2 Certificate message with a raw public key (RFC 7250 3): the
// SPKI with a three-byte length, not a list.
func (m *certificateMsg) marshalRawKey() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			if len(m.certificates) > 0 {
				b.AddBytes(m.certificates[0])
			}
		})
	})
	return b.Bytes()
}

func (m *certificateMsg) unmarshalRawKey(data []byte) bool {
	s := cryptobyte.String(data)
	var body, spki cryptobyte.String
	if !s.Skip(1) || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() ||
		!body.ReadUint24LengthPrefixed(&spki) || !body.Empty() {
		return false
	}
	m.certificates = nil
	if len(spki) > 0 { // an empty one: no certificate
		m.certificates = [][]byte{slices.Clone([]byte(spki))}
	}
	return true
}

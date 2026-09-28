// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/hmac"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/ccm"
	"github.com/cB-Abhinav-Gautam/tlsx/internal/tls13"
)

// Pre-shared keys.
//
// TLS 1.2: the PSK key exchanges of RFC 4279 (PSK, DHE_PSK) and RFC 5489
// (ECDHE_PSK) with the suites of RFC 4279, RFC 5487, RFC 5489, RFC 6655,
// RFC 7905 and RFC 8442 listed below. The legacy HMAC-SHA-1 CBC suites
// (TLS_PSK_WITH_AES_128_CBC_SHA and the like) are for old devices; they
// also work in TLS 1.0 and 1.1. A TLS 1.2 identity may be empty. None is offered unless Config.CipherSuites
// lists it and Config.Ext.PSK is set; a PSK suite uses no certificate, so
// a server with only PSKs needs no Config.Certificates.
//
// TLS 1.3: external PSKs (RFC 8446 2.2, 4.2.11; binder label "ext
// binder"), with psk_dhe_ke and, when allowed, psk_ke (no (EC)DHE, no
// forward secrecy). Following RFC 9257, the client offers one external
// identity, psk_dhe_ke is preferred, and a PSK is meant for one pair of
// peers. Imported PSKs (RFC 9258) are not implemented.
//
// Sessions of TLS 1.2 PSK handshakes are resumed only with
// PSKConfig.Resumption, bound to their PSK (x_psk_resume.go); sessions of
// TLS 1.3 external-PSK handshakes are neither resumed nor ticketed.

// TLS 1.2 PSK cipher suites tlsx adds.
const (
	TLS_PSK_WITH_AES_128_CBC_SHA256             uint16 = 0x00ae // RFC 5487
	TLS_PSK_WITH_AES_256_CBC_SHA384             uint16 = 0x00af // RFC 5487
	TLS_PSK_WITH_AES_128_GCM_SHA256             uint16 = 0x00a8 // RFC 5487
	TLS_PSK_WITH_AES_256_GCM_SHA384             uint16 = 0x00a9 // RFC 5487
	TLS_PSK_WITH_AES_128_CCM                    uint16 = 0xc0a4 // RFC 6655
	TLS_PSK_WITH_AES_256_CCM                    uint16 = 0xc0a5 // RFC 6655
	TLS_PSK_WITH_AES_128_CCM_8                  uint16 = 0xc0a8 // RFC 6655
	TLS_PSK_WITH_AES_256_CCM_8                  uint16 = 0xc0a9 // RFC 6655
	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256       uint16 = 0xccab // RFC 7905
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256         uint16 = 0x00b2 // RFC 5487
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384         uint16 = 0x00b3 // RFC 5487
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256         uint16 = 0x00aa // RFC 5487
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384         uint16 = 0x00ab // RFC 5487
	TLS_DHE_PSK_WITH_AES_128_CCM                uint16 = 0xc0a6 // RFC 6655
	TLS_DHE_PSK_WITH_AES_256_CCM                uint16 = 0xc0a7 // RFC 6655
	TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xccad // RFC 7905
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256       uint16 = 0xc037 // RFC 5489
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384       uint16 = 0xc038 // RFC 5489
	TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256       uint16 = 0xd001 // RFC 8442
	TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384       uint16 = 0xd002 // RFC 8442
	TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256     uint16 = 0xd003 // RFC 8442
	TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256       uint16 = 0xd005 // RFC 8442
	TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xccac // RFC 7905

	// Legacy suites with HMAC-SHA-1, for old devices: CBC only (MAC then
	// encrypt, or encrypt_then_mac when negotiated), usable from TLS 1.0.
	TLS_PSK_WITH_AES_128_CBC_SHA       uint16 = 0x008c // RFC 4279
	TLS_PSK_WITH_AES_256_CBC_SHA       uint16 = 0x008d // RFC 4279
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA   uint16 = 0x0090 // RFC 4279
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA   uint16 = 0x0091 // RFC 4279
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA uint16 = 0xc035 // RFC 5489
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA uint16 = 0xc036 // RFC 5489
)

// PSKConfig configures pre-shared keys (Config.Ext.PSK).
type PSKConfig struct {
	// Identity and Key are what a client offers: the psk_identity of TLS
	// 1.2 and the external identity of TLS 1.3.
	Identity, Key []byte
	// ClientKey, if set, chooses a TLS 1.2 client's identity and key from
	// the server's psk_identity_hint (empty when none was sent); it takes
	// precedence over Identity and Key there.
	ClientKey func(hint []byte) (identity, key []byte, err error)

	// Hint is a TLS 1.2 server's psk_identity_hint (none when empty).
	Hint []byte
	// Lookup gives a server the key of an identity: nil (and no error)
	// for an identity it does not know. It runs in the handshake with the
	// handshake's context and must be safe for concurrent use.
	Lookup func(ctx context.Context, identity []byte) (key []byte, err error)

	// TLS13 offers (client) and accepts (server) the PSK as an external
	// PSK in TLS 1.3. Off: TLS 1.3 handshakes use certificates as usual.
	TLS13 bool
	// Hash is the TLS 1.3 PSK's hash, crypto.SHA256 (the default) or
	// crypto.SHA384; only TLS 1.3 suites with that hash can use it.
	Hash crypto.Hash
	// Resumption allows TLS 1.2 PSK sessions to be resumed (session tickets
	// as upstream, session IDs with Config.Ext.ServerSessionCache and
	// ClientSessionIDs). A session stays bound to its PSK: before resuming
	// it, a server calls Lookup and a client uses Identity and Key or
	// ClientKey (with the hint of the session's full handshake), and the
	// session is resumed only if the identity still has the same key, so
	// removing or changing a key ends resumption of its sessions. Off:
	// every PSK handshake is a full one. TLS 1.3 sessions of external-PSK
	// handshakes are not resumed.
	Resumption bool

	// AllowNoDHE allows TLS 1.3 psk_ke, a key exchange without (EC)DHE
	// and so without forward secrecy. A client then offers both modes; a
	// server uses psk_ke only when the client offers nothing else or
	// PreferNoDHE is set.
	AllowNoDHE, PreferNoDHE bool
}

func (p *PSKConfig) hash() crypto.Hash {
	if p.Hash == crypto.SHA384 {
		return crypto.SHA384
	}
	return crypto.SHA256
}

func (p *PSKConfig) clientReady() bool {
	return p != nil && (p.ClientKey != nil || len(p.Identity) > 0 && len(p.Key) > 0)
}

func (p *PSKConfig) serverReady() bool { return p != nil && p.Lookup != nil }

// suitePSK marks a TLS 1.2 PSK suite; suitePSKDHE and suitePSKECDHE its
// key exchange (plain PSK otherwise).
const (
	suitePSK      = 1 << 12
	suitePSKDHE   = 1 << 13
	suitePSKECDHE = 1 << 14
)

// IsPSKSuite reports a TLS 1.2 pre-shared key cipher suite.
func IsPSKSuite(id uint16) bool {
	c := cipherSuiteByID(id)
	return c != nil && c.flags&suitePSK != 0
}

var pskSuiteNames = map[uint16]string{
	TLS_PSK_WITH_AES_128_CBC_SHA256:             "TLS_PSK_WITH_AES_128_CBC_SHA256",
	TLS_PSK_WITH_AES_256_CBC_SHA384:             "TLS_PSK_WITH_AES_256_CBC_SHA384",
	TLS_PSK_WITH_AES_128_GCM_SHA256:             "TLS_PSK_WITH_AES_128_GCM_SHA256",
	TLS_PSK_WITH_AES_256_GCM_SHA384:             "TLS_PSK_WITH_AES_256_GCM_SHA384",
	TLS_PSK_WITH_AES_128_CCM:                    "TLS_PSK_WITH_AES_128_CCM",
	TLS_PSK_WITH_AES_256_CCM:                    "TLS_PSK_WITH_AES_256_CCM",
	TLS_PSK_WITH_AES_128_CCM_8:                  "TLS_PSK_WITH_AES_128_CCM_8",
	TLS_PSK_WITH_AES_256_CCM_8:                  "TLS_PSK_WITH_AES_256_CCM_8",
	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:       "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:         "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA384:         "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:         "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
	TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:         "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
	TLS_DHE_PSK_WITH_AES_128_CCM:                "TLS_DHE_PSK_WITH_AES_128_CCM",
	TLS_DHE_PSK_WITH_AES_256_CCM:                "TLS_DHE_PSK_WITH_AES_256_CCM",
	TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:   "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:       "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:       "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
	TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256:       "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
	TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384:       "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
	TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256:     "TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256",
	TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256:       "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",
	TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
	TLS_PSK_WITH_AES_128_CBC_SHA:                "TLS_PSK_WITH_AES_128_CBC_SHA",
	TLS_PSK_WITH_AES_256_CBC_SHA:                "TLS_PSK_WITH_AES_256_CBC_SHA",
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA:            "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
	TLS_DHE_PSK_WITH_AES_256_CBC_SHA:            "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA:          "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA:          "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
}

func init() {
	const tls12 = suiteTLS12 | suitePSK
	d, e := suitePSKDHE, suitePSKECDHE
	s := suiteSHA384
	suites := []*cipherSuite{
		{TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, pskKA, tls12 | e, nil, nil, aeadAESGCM},
		{TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, pskKA, tls12 | e | s, nil, nil, aeadAESGCM},
		{TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, pskKA, tls12 | e, nil, nil, aeadChaCha20Poly1305},
		{TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256, 16, 0, 4, pskKA, tls12 | e, nil, nil, aeadAESCCM12(16)},
		{TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256, 16, 0, 4, pskKA, tls12 | e, nil, nil, aeadAESCCM12(8)},
		{TLS_DHE_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, pskKA, tls12 | d, nil, nil, aeadAESGCM},
		{TLS_DHE_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, pskKA, tls12 | d | s, nil, nil, aeadAESGCM},
		{TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, pskKA, tls12 | d, nil, nil, aeadChaCha20Poly1305},
		{TLS_DHE_PSK_WITH_AES_128_CCM, 16, 0, 4, pskKA, tls12 | d, nil, nil, aeadAESCCM12(16)},
		{TLS_DHE_PSK_WITH_AES_256_CCM, 32, 0, 4, pskKA, tls12 | d, nil, nil, aeadAESCCM12(16)},
		{TLS_PSK_WITH_AES_128_GCM_SHA256, 16, 0, 4, pskKA, tls12, nil, nil, aeadAESGCM},
		{TLS_PSK_WITH_AES_256_GCM_SHA384, 32, 0, 4, pskKA, tls12 | s, nil, nil, aeadAESGCM},
		{TLS_PSK_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, pskKA, tls12, nil, nil, aeadChaCha20Poly1305},
		{TLS_PSK_WITH_AES_128_CCM, 16, 0, 4, pskKA, tls12, nil, nil, aeadAESCCM12(16)},
		{TLS_PSK_WITH_AES_256_CCM, 32, 0, 4, pskKA, tls12, nil, nil, aeadAESCCM12(16)},
		{TLS_PSK_WITH_AES_128_CCM_8, 16, 0, 4, pskKA, tls12, nil, nil, aeadAESCCM12(8)},
		{TLS_PSK_WITH_AES_256_CCM_8, 32, 0, 4, pskKA, tls12, nil, nil, aeadAESCCM12(8)},
		{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, pskKA, tls12 | e, cipherAES, macSHA256, nil},
		{TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384, 32, 48, 16, pskKA, tls12 | e | s, cipherAES, macSHA384, nil},
		{TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, pskKA, tls12 | d, cipherAES, macSHA256, nil},
		{TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, 32, 48, 16, pskKA, tls12 | d | s, cipherAES, macSHA384, nil},
		{TLS_PSK_WITH_AES_128_CBC_SHA256, 16, 32, 16, pskKA, tls12, cipherAES, macSHA256, nil},
		{TLS_PSK_WITH_AES_256_CBC_SHA384, 32, 48, 16, pskKA, tls12 | s, cipherAES, macSHA384, nil},
		// Legacy, HMAC-SHA-1, from TLS 1.0 on (no suiteTLS12), last.
		{TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, suitePSK | e, cipherAES, macSHA1, nil},
		{TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, suitePSK | e, cipherAES, macSHA1, nil},
		{TLS_DHE_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, suitePSK | d, cipherAES, macSHA1, nil},
		{TLS_DHE_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, suitePSK | d, cipherAES, macSHA1, nil},
		{TLS_PSK_WITH_AES_128_CBC_SHA, 16, 20, 16, pskKA, suitePSK, cipherAES, macSHA1, nil},
		{TLS_PSK_WITH_AES_256_CBC_SHA, 32, 20, 16, pskKA, suitePSK, cipherAES, macSHA1, nil},
	}
	var ids []uint16
	for _, c := range suites {
		cipherSuites = append(cipherSuites, c)
		ids = append(ids, c.id)
		disabledCipherSuites[c.id] = true
		tlsxSuiteNames[c.id] = pskSuiteNames[c.id]
	}
	// A client offers PSK suites only when it has a PSK and a server
	// selects them only when it can look keys up, so they come first:
	// forward-secret AEADs, then the plain PSK AEADs, then CBC.
	for _, l := range []*[]uint16{&cipherSuitesPreferenceOrder, &cipherSuitesPreferenceOrderNoAES} {
		*l = slices.Insert(*l, 0, ids...)
	}
}

// Adapted from Go's crypto/tls/cipher_suites.go: aeadAESGCM (with AES-CCM in
// place of AES-GCM).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// aeadAESCCM12 is AES-CCM for TLS 1.2 (RFC 6655 3): a 4-byte salt from the
// key block and an 8-byte explicit nonce in each record.
func aeadAESCCM12(tagLen int) func(key, noncePrefix []byte) aead {
	return func(key, noncePrefix []byte) aead {
		if len(noncePrefix) != noncePrefixLength {
			panic("tls: internal error: wrong nonce length")
		}
		b, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		a, err := ccm.New(b, aeadNonceLength, tagLen)
		if err != nil {
			panic(err)
		}
		ret := &prefixNonceAEAD{aead: a}
		copy(ret.nonce[:], noncePrefix)
		return ret
	}
}

// pskKA is the keyAgreement slot of the PSK suites. Their handshakes run
// in doFullHandshakePSK (they need no certificate and carry an identity),
// never through the keyAgreement interface.
func pskKA(version uint16) keyAgreement { return pskKeyAgreementStub{} }

type pskKeyAgreementStub struct{}

var errPSKKeyAgreement = errors.New("tlsx: internal error: PSK suite outside the PSK handshake")

func (pskKeyAgreementStub) generateServerKeyExchange(*Config, *Certificate, *clientHelloMsg, *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	return nil, errPSKKeyAgreement
}
func (pskKeyAgreementStub) processClientKeyExchange(*Config, *Certificate, *clientKeyExchangeMsg, uint16) ([]byte, error) {
	return nil, errPSKKeyAgreement
}
func (pskKeyAgreementStub) generateClientKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	return nil, nil, errPSKKeyAgreement
}
func (pskKeyAgreementStub) processServerKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error {
	return errPSKKeyAgreement
}

// pskPremaster is the TLS 1.2 PSK premaster secret (RFC 4279 2):
// other_secret and the key, each with a two-byte length. Plain PSK uses
// as many zero bytes as the key has.
func pskPremaster(other, key []byte) []byte {
	if other == nil {
		other = make([]byte, len(key))
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(other) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(key) })
	return b.BytesOrPanic()
}

// ErrUnknownPSKIdentity is a server's error for an identity Lookup does
// not know (the client is sent unknown_psk_identity).
var ErrUnknownPSKIdentity = errors.New("tlsx: unknown PSK identity")

// checkPSKLengths applies the length limits: a TLS 1.2 identity may be
// empty (RFC 4279 2: psk_identity<0..2^16-1>), a TLS 1.3 one may not
// (RFC 8446 4.2.11: identity<1..2^16-1>).
func checkPSKLengths(identity, key []byte, tls13 bool) error {
	if tls13 && len(identity) == 0 || len(identity) > 0xffff {
		return errors.New("tlsx: a PSK identity must have 1 to 65535 bytes")
	}
	if len(key) == 0 || len(key) > 0xffff {
		return errors.New("tlsx: a PSK must have 1 to 65535 bytes")
	}
	return nil
}

// cipherSuiteOkPSK decides a server's use of a PSK suite (TLS 1.2; the
// legacy SHA-1 suites from TLS 1.0).
func (hs *serverHandshakeState) cipherSuiteOkPSK(c *cipherSuite) bool {
	cfg := hs.c.config
	if !cfg.Ext.PSK.serverReady() || hs.c.vers < VersionTLS12 && c.flags&suiteTLS12 != 0 {
		return false
	}
	switch {
	case c.flags&suitePSKECDHE != 0:
		return pskECDHECurve(cfg, hs.clientHello) != 0
	case c.flags&suitePSKDHE != 0:
		return selectDHEGroup(cfg, hs.clientHello) != nil
	}
	return true
}

// pskECDHECurve is the first elliptic curve the client offers that we
// allow (0: none).
func pskECDHECurve(cfg *Config, ch *clientHelloMsg) CurveID {
	for _, id := range ch.supportedCurves {
		if cfg.supportsCurve(VersionTLS12, id) && !isFFDHE(id) && !isPQKeyExchange(id) {
			if _, ok := curveForCurveID(id); ok || isBrainpool(id) {
				return id
			}
		}
	}
	return 0
}

// getCertificateX is getCertificate for a TLS 1.2 server: a server with
// pre-shared keys and no certificate goes on, with PSK suites only.
func (c *Conn) getCertificateX(chi *ClientHelloInfo) (*Certificate, error) {
	cert, err := c.config.getCertificate(chi)
	if err == errNoCertificates && c.config.Ext.PSK.serverReady() {
		return &Certificate{}, nil
	}
	return cert, err
}

// Adapted from Go's crypto/tls/handshake_server.go: doFullHandshake (the
// ServerHello and transcript steps, VerifyConnection); the messages are PSK's.
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// doFullHandshakePSK is a TLS 1.2 server's full handshake with a PSK
// suite: ServerHello, [ServerKeyExchange], ServerHelloDone; then the
// client's ClientKeyExchange with its identity. No certificates.
func (hs *serverHandshakeState) doFullHandshakePSK() error {
	c := hs.c
	p := c.config.Ext.PSK
	if hs.clientHello.serverName != "" {
		hs.hello.serverNameAck = true
	}
	// A session ticket only when the session can be resumed (bound to the
	// PSK, x_psk_resume.go), as doFullHandshake decides otherwise.
	hs.hello.ticketSupported = p.Resumption && hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.ocspStapling = false
	hs.hello.scts = nil
	hs.hello.cipherSuite = hs.suite.id
	if err := hs.serverHelloExtensions(); err != nil {
		return err
	}
	if !p.Resumption {
		hs.hello.sessionId = nil // no session to resume by ID either
	}
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	if err := transcriptMsg(hs.clientHello, &hs.finishedHash); err != nil {
		return err
	}
	if _, err := c.writeHandshakeRecord(hs.hello, &hs.finishedHash); err != nil {
		return err
	}

	// ServerKeyExchange: the hint, then the (EC)DH parameters, unsigned.
	var ecdh *ecdheKeyAgreement
	var dh *ffdheGroup
	var dhPriv []byte
	var params []byte
	switch {
	case hs.suite.flags&suitePSKECDHE != 0:
		ecdh = &ecdheKeyAgreement{version: c.vers, curveID: pskECDHECurve(c.config, hs.clientHello)}
		pub, err := ecdh.generateKey(c.config.rand())
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		params = append([]byte{3, byte(ecdh.curveID >> 8), byte(ecdh.curveID), byte(len(pub))}, pub...)
		c.curveID = ecdh.curveID
	case hs.suite.flags&suitePSKDHE != 0:
		dh = selectDHEGroup(c.config, hs.clientHello)
		priv, pub, err := dh.generate(c.config.rand())
		if err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
		dhPriv, params = priv, dheParams(dh, pub)
		c.curveID = dh.id
	}
	if len(p.Hint) > 0xffff {
		c.sendAlert(alertInternalError)
		return errors.New("tlsx: PSK identity hint too long")
	}
	if params != nil || len(p.Hint) > 0 {
		var b cryptobyte.Builder
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(p.Hint) })
		b.AddBytes(params)
		if _, err := c.writeHandshakeRecord(&serverKeyExchangeMsg{key: b.BytesOrPanic()}, &hs.finishedHash); err != nil {
			return err
		}
	}
	if _, err := c.writeHandshakeRecord(new(serverHelloDoneMsg), &hs.finishedHash); err != nil {
		return err
	}
	if _, err := c.flush(); err != nil {
		return err
	}

	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	s := cryptobyte.String(ckx.ciphertext)
	var identity []byte
	if !readUint16LengthPrefixed(&s, &identity) {
		c.sendAlert(alertDecodeError)
		return errClientKeyExchange
	}
	identity = append([]byte{}, identity...) // non-nil: an empty identity is still one
	var other []byte
	switch {
	case ecdh != nil:
		var pub []byte
		if !readUint8LengthPrefixed(&s, &pub) || !s.Empty() {
			c.sendAlert(alertDecodeError)
			return errClientKeyExchange
		}
		if other, err = ecdh.sharedSecret(pub); err != nil {
			c.sendAlert(alertIllegalParameter)
			return errClientKeyExchange
		}
	case dh != nil:
		var yc []byte
		if !readUint16LengthPrefixed(&s, &yc) || !s.Empty() || len(yc) == 0 {
			c.sendAlert(alertDecodeError)
			return errClientKeyExchange
		}
		z, err := dh.shared(dhPriv, yc)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return errClientKeyExchange
		}
		other = trimZeros(z)
	default:
		if !s.Empty() {
			c.sendAlert(alertDecodeError)
			return errClientKeyExchange
		}
	}
	if c.handshakes > 0 && !bytes.Equal(identity, c.x.pskIdentity) {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tlsx: the PSK identity changed in a renegotiation")
	}
	key, err := p.Lookup(hs.ctx, identity)
	if err != nil {
		c.sendAlert(alertInternalError)
		return fmt.Errorf("tlsx: PSK lookup: %w", err)
	}
	if len(key) == 0 {
		c.sendAlert(alertUnknownPSKIdentity)
		return fmt.Errorf("%w %q", ErrUnknownPSKIdentity, identity)
	}
	c.x.pskIdentity = slices.Clone(identity)
	c.x.bindPSK(p, identity, p.Hint, key)
	hs.masterSecret = hs.pskMasterSecret(pskPremaster(other, key))
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.clientHello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}
	return nil
}

// Adapted from Go's crypto/tls/handshake_server.go: doFullHandshake (the
// extended master secret derivation).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
func (hs *serverHandshakeState) pskMasterSecret(pms []byte) []byte {
	c := hs.c
	if hs.hello.extendedMasterSecret {
		c.extMasterSecret = true
		return extMasterFromPreMasterSecret(c.vers, hs.suite, pms, hs.finishedHash.Sum())
	}
	return masterFromPreMasterSecret(c.vers, hs.suite, pms, hs.clientHello.random, hs.hello.random)
}

// Adapted from Go's crypto/tls/handshake_client.go: doFullHandshake (extended
// master secret, key log, VerifyConnection) and key_agreement.go:
// processServerKeyExchange (the curve checks); the messages are PSK's.
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// doFullHandshakePSK is a TLS 1.2 client's full handshake with a PSK
// suite: it reads [ServerKeyExchange] and ServerHelloDone and answers
// with its identity (and (EC)DH share).
func (hs *clientHandshakeState) doFullHandshakePSK() error {
	c := hs.c
	p := c.config.Ext.PSK
	if !p.clientReady() {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tlsx: server selected a PSK suite and the client has no PSK")
	}
	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	var hint []byte
	var ckxPublic []byte
	var other []byte
	skx, ok := msg.(*serverKeyExchangeMsg)
	if ok {
		s := cryptobyte.String(skx.key)
		if !readUint16LengthPrefixed(&s, &hint) {
			c.sendAlert(alertDecodeError)
			return errServerKeyExchange
		}
		switch {
		case hs.suite.flags&suitePSKECDHE != 0:
			var curve uint16
			var pub []byte
			var typ uint8
			if !s.ReadUint8(&typ) || typ != 3 || !s.ReadUint16(&curve) || !readUint8LengthPrefixed(&s, &pub) || !s.Empty() {
				c.sendAlert(alertDecodeError)
				return errServerKeyExchange
			}
			id := CurveID(curve)
			if !slices.Contains(hs.hello.supportedCurves, id) || isFFDHE(id) {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: server selected unoffered curve")
			}
			if _, ok := curveForCurveID(id); !ok && !isBrainpool(id) {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: server selected unsupported curve")
			}
			ka := &ecdheKeyAgreement{version: c.vers, curveID: id}
			if ckxPublic, err = ka.generateKey(c.config.rand()); err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			if other, err = ka.sharedSecret(pub); err != nil {
				c.sendAlert(alertIllegalParameter)
				return errServerKeyExchange
			}
			c.curveID = id
			ckxPublic = append([]byte{byte(len(ckxPublic))}, ckxPublic...)
		case hs.suite.flags&suitePSKDHE != 0:
			var pBytes, gBytes, ys []byte
			if !readUint16LengthPrefixed(&s, &pBytes) || !readUint16LengthPrefixed(&s, &gBytes) || !readUint16LengthPrefixed(&s, &ys) || !s.Empty() {
				c.sendAlert(alertDecodeError)
				return errServerKeyExchange
			}
			g := ffdheGroupByParams(pBytes, gBytes)
			if g == nil {
				c.sendAlert(alertInsufficientSecurity)
				return errors.New("tlsx: server offered a finite field group that is not one of RFC 7919")
			}
			if slices.ContainsFunc(hs.hello.supportedCurves, isFFDHE) && !slices.Contains(hs.hello.supportedCurves, g.id) || !c.config.supportsCurve(VersionTLS12, g.id) {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tlsx: server selected a finite field group not allowed by the configuration")
			}
			priv, pub, err := g.generate(c.config.rand())
			if err != nil {
				c.sendAlert(alertInternalError)
				return err
			}
			z, err := g.shared(priv, ys)
			if err != nil {
				c.sendAlert(alertIllegalParameter)
				return errServerKeyExchange
			}
			other = trimZeros(z)
			c.curveID = g.id
			ckxPublic = append([]byte{byte(len(pub) >> 8), byte(len(pub))}, pub...)
		default:
			if !s.Empty() {
				c.sendAlert(alertDecodeError)
				return errServerKeyExchange
			}
		}
		if msg, err = c.readHandshake(&hs.finishedHash); err != nil {
			return err
		}
	} else if hs.suite.flags&(suitePSKECDHE|suitePSKDHE) != 0 {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(skx, msg)
	}
	shd, ok := msg.(*serverHelloDoneMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(shd, msg)
	}

	identity, key := p.Identity, p.Key
	if p.ClientKey != nil {
		if identity, key, err = p.ClientKey(slices.Clone(hint)); err != nil {
			c.sendAlert(alertInternalError)
			return err
		}
	}
	if err := checkPSKLengths(identity, key, false); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}
	identity = append([]byte{}, identity...) // non-nil: an empty identity is still one
	if c.handshakes > 0 && !bytes.Equal(identity, c.x.pskIdentity) {
		c.sendAlert(alertHandshakeFailure)
		return errors.New("tlsx: the PSK identity changed in a renegotiation")
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(identity) })
	b.AddBytes(ckxPublic)
	if _, err := c.writeHandshakeRecord(&clientKeyExchangeMsg{ciphertext: b.BytesOrPanic()}, &hs.finishedHash); err != nil {
		return err
	}
	c.x.pskIdentity = slices.Clone(identity)
	c.x.pskHint = slices.Clone(hint)
	c.x.bindPSK(p, identity, hint, key)
	pms := pskPremaster(other, key)
	if hs.serverHello.extendedMasterSecret {
		c.extMasterSecret = true
		hs.masterSecret = extMasterFromPreMasterSecret(c.vers, hs.suite, pms, hs.finishedHash.Sum())
	} else {
		hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, pms, hs.hello.random, hs.serverHello.random)
	}
	if err := c.config.writeKeyLog(keyLogLabelTLS12, hs.hello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return errors.New("tls: failed to write to key log: " + err.Error())
	}
	if c.config.VerifyConnection != nil {
		if err := c.config.VerifyConnection(c.connectionStateLocked()); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}
	hs.finishedHash.discardHandshakeBuffer()
	return nil
}

// ---- TLS 1.3 external PSKs ---------------------------------------------------

// tls13SuiteForHash is the TLS 1.3 suite a PSK of hash h is recorded with.
func tls13SuiteForHash(h crypto.Hash) uint16 {
	if h == crypto.SHA384 {
		return TLS_AES_256_GCM_SHA384
	}
	return TLS_AES_128_GCM_SHA256
}

// Adapted from Go's crypto/tls/handshake_client.go: loadSession (the binder
// placeholder, early secret, binder key and computeAndUpdatePSK call).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// loadExternalPSK offers the configured external PSK in a TLS 1.3
// ClientHello that offers no resumption ticket. The session it returns
// stands for the PSK in the upstream code (processServerHello, the
// HelloRetryRequest binders).
func (c *Conn) loadExternalPSK(hello *clientHelloMsg) (*SessionState, *tls13.EarlySecret, []byte, error) {
	p := c.config.Ext.PSK
	if p == nil || !p.TLS13 || len(p.Identity) == 0 || len(p.Key) == 0 || c.quic != nil || c.handshakes > 0 ||
		len(hello.supportedVersions) == 0 || hello.supportedVersions[0] != VersionTLS13 ||
		len(hello.encryptedClientHello) > 0 || len(hello.pskIdentities) > 0 {
		return nil, nil, nil, nil
	}
	if err := checkPSKLengths(p.Identity, p.Key, true); err != nil {
		return nil, nil, nil, err
	}
	suite := cipherSuiteTLS13ByID(tls13SuiteForHash(p.hash()))
	if !slices.ContainsFunc(hello.cipherSuites, func(id uint16) bool {
		s := cipherSuiteTLS13ByID(id)
		return s != nil && s.hash == suite.hash
	}) {
		return nil, nil, nil, errors.New("tlsx: no TLS 1.3 cipher suite offered for the PSK's hash")
	}
	hello.pskModes = []uint8{pskModeDHE}
	if p.AllowNoDHE {
		hello.pskModes = append(hello.pskModes, pskModePlain)
	}
	// RFC 8446 4.2.11: an external identity's obfuscated_ticket_age is 0.
	hello.pskIdentities = []pskIdentity{{label: slices.Clone(p.Identity)}}
	hello.pskBinders = [][]byte{make([]byte, suite.hash.Size())}
	earlySecret := tls13.NewEarlySecret(suite.hash.New, p.Key)
	binderKey := earlySecret.ExternalBinderKey()
	if err := computeAndUpdatePSK(hello, binderKey, suite.hash.New(), suite.finishedHash); err != nil {
		return nil, nil, nil, err
	}
	c.x.pskOffered = hello.pskIdentities[0].label
	session := &SessionState{version: VersionTLS13, cipherSuite: suite.id, secret: p.Key,
		createdAt: uint64(c.config.time().Unix())}
	return session, earlySecret, binderKey, nil
}

// externalPSKAge keeps obfuscated_ticket_age at 0 for an external PSK in
// the second ClientHello.
func (x *connExt) externalPSKAge(hello *clientHelloMsg) {
	if x.pskOffered != nil && len(hello.pskIdentities) == 1 {
		hello.pskIdentities[0].obfuscatedTicketAge = 0
	}
}

// externalPSKAccepted records a TLS 1.3 server's choice of our external
// PSK: no resumption, the identity in the connection state.
func (c *Conn) externalPSKAccepted() {
	if c.x.pskOffered != nil {
		c.didResume = false
		c.x.pskIdentity = c.x.pskOffered
	}
}

// pskOnlyAllowed says a TLS 1.3 client accepts a ServerHello without
// key_share: psk_ke with our external PSK.
func (c *Conn) pskOnlyAllowed(sh *serverHelloMsg) bool {
	p := c.config.Ext.PSK
	return c.x.pskOffered != nil && p != nil && p.AllowNoDHE && sh.selectedIdentityPresent && sh.selectedIdentity == 0
}

// pskOnlyKeyExchange stands for "no key exchange" (psk_ke): the TLS 1.3
// handshake secret then takes zeros as its input (RFC 8446 7.1).
type pskOnlyKeyExchange struct{}

var errPSKOnly = errors.New("tlsx: internal error: psk_ke has no key share")

func (pskOnlyKeyExchange) keyShares(io.Reader) (*keySharePrivateKeys, []keyShare, error) {
	return nil, nil, errPSKOnly
}
func (pskOnlyKeyExchange) serverSharedSecret(io.Reader, []byte) ([]byte, keyShare, error) {
	return nil, keyShare{}, errPSKOnly
}
func (pskOnlyKeyExchange) clientSharedSecret(*keySharePrivateKeys, []byte) ([]byte, error) {
	return nil, nil
}

// Adapted from Go's crypto/tls/handshake_server_tls13.go: checkForResumption
// (the identity loop and binder verification, with the external binder key).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// checkExternalPSK is a TLS 1.3 server's check of the client's PSK
// identities against Config.Ext.PSK. done says it selected one (or
// failed); otherwise the tickets are tried as upstream.
func (hs *serverHandshakeStateTLS13) checkExternalPSK() (done bool, err error) {
	c := hs.c
	p := c.config.Ext.PSK
	if !p.serverReady() || !p.TLS13 || c.quic != nil || len(hs.clientHello.pskIdentities) == 0 {
		return false, nil
	}
	dhe := slices.Contains(hs.clientHello.pskModes, pskModeDHE)
	plain := p.AllowNoDHE && slices.Contains(hs.clientHello.pskModes, pskModePlain)
	if !dhe && !plain {
		return false, nil
	}
	if len(hs.clientHello.pskIdentities) != len(hs.clientHello.pskBinders) {
		c.sendAlert(alertIllegalParameter)
		return true, errors.New("tls: invalid or missing PSK binders")
	}
	if cipherSuiteTLS13ByID(tls13SuiteForHash(p.hash())).hash != hs.suite.hash {
		return false, nil
	}
	for i, identity := range hs.clientHello.pskIdentities {
		if i >= maxClientPSKIdentities {
			break
		}
		if len(identity.label) == 0 || len(identity.label) > 0xffff {
			continue
		}
		key, err := p.Lookup(hs.ctx, identity.label)
		if err != nil {
			c.sendAlert(alertInternalError)
			return true, fmt.Errorf("tlsx: PSK lookup: %w", err)
		}
		if len(key) == 0 {
			continue
		}
		earlySecret := tls13.NewEarlySecret(hs.suite.hash.New, key)
		transcript := cloneHash(hs.transcript, hs.suite.hash)
		if transcript == nil {
			c.sendAlert(alertInternalError)
			return true, errors.New("tls: internal error: failed to clone hash")
		}
		helloBytes, err := hs.clientHello.marshalWithoutBinders()
		if err != nil {
			c.sendAlert(alertInternalError)
			return true, err
		}
		transcript.Write(helloBytes)
		binder := hs.suite.finishedHash(earlySecret.ExternalBinderKey(), transcript)
		if !hmac.Equal(hs.clientHello.pskBinders[i], binder) {
			c.sendAlert(alertDecryptError)
			return true, errors.New("tls: invalid PSK binder")
		}
		hs.earlySecret = earlySecret
		hs.usingPSK = true
		hs.hello.selectedIdentityPresent = true
		hs.hello.selectedIdentity = uint16(i)
		c.x.pskIdentity = slices.Clone(identity.label)
		if !dhe || plain && p.PreferNoDHE {
			// psk_ke: no key_share in the ServerHello, zeros as the
			// (EC)DHE input.
			hs.sharedKey = nil
			hs.hello.serverShare = keyShare{}
			c.curveID = 0
		}
		return true, nil
	}
	return false, nil
}

// noSessionCache says the connection's session must not be cached,
// ticketed or resumed: a raw public key handshake, whose identity a
// resumption would not carry, or a PSK handshake unless the session is
// bound to its PSK (PSKConfig.Resumption, TLS 1.2; x_psk_resume.go).
func (x *connExt) noSessionCache() bool {
	return x.pskIdentity != nil && x.pskBinding == nil || x.peerRawKey || x.ownRawKey
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"errors"
	"time"
)

// This file holds the public types tlsx adds to the upstream crypto/tls
// API. Upstream structs carry them in one field each (Config.Ext,
// ConnectionState.Ext, ClientHelloInfo.Ext, Certificate.ChainOCSPStaples)
// so upstream changes merge cleanly (UPSTREAM.md).

// Extension numbers tlsx adds.
const (
	extensionMaxFragmentLength uint16 = 1  // RFC 6066, Section 4
	extensionTrustedCAKeys     uint16 = 3  // RFC 6066, Section 6
	extensionStatusRequestV2   uint16 = 17 // RFC 6961
	extensionEncryptThenMAC    uint16 = 22 // RFC 7366
)

// Signature schemes tlsx adds.
const (
	// RSASSA-PSS with a public key of OID id-RSASSA-PSS (RFC 8446 4.2.3).
	PSSPSSWithSHA256 SignatureScheme = 0x0809
	PSSPSSWithSHA384 SignatureScheme = 0x080a
	PSSPSSWithSHA512 SignatureScheme = 0x080b

	// ECDSA on the brainpool curves in TLS 1.3 (RFC 8734).
	ECDSABrainpoolP256r1TLS13WithSHA256 SignatureScheme = 0x081a
	ECDSABrainpoolP384r1TLS13WithSHA384 SignatureScheme = 0x081b
	ECDSABrainpoolP512r1TLS13WithSHA512 SignatureScheme = 0x081c
)

// Groups tlsx adds.
const (
	// Finite field groups of RFC 7919, for TLS 1.3 key shares and the TLS
	// 1.2 DHE suites.
	FFDHE2048 CurveID = 256
	FFDHE3072 CurveID = 257
	FFDHE4096 CurveID = 258

	// Brainpool curves for TLS 1.2 ECDHE (RFC 7027) and TLS 1.3 (RFC 8734).
	BrainpoolP256r1      CurveID = 26
	BrainpoolP384r1      CurveID = 27
	BrainpoolP512r1      CurveID = 28
	BrainpoolP256r1TLS13 CurveID = 31
	BrainpoolP384r1TLS13 CurveID = 32
	BrainpoolP512r1TLS13 CurveID = 33
)

// Cipher suites tlsx adds.
const (
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256     uint16 = 0x009e // RFC 5288
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384     uint16 = 0x009f // RFC 5288
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 uint16 = 0xc024 // RFC 5289
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   uint16 = 0xc028 // RFC 5289
	TLS_AES_128_CCM_SHA256                  uint16 = 0x1304 // RFC 8446 B.4
	TLS_AES_128_CCM_8_SHA256                uint16 = 0x1305 // RFC 8446 B.4
	// Integrity-only TLS 1.3 suites (RFC 9150): no confidentiality.
	TLS_SHA256_SHA256 uint16 = 0xc0b4
	TLS_SHA384_SHA384 uint16 = 0xc0b5
	// TLS 1.2 integrity-only suite (RFC 5246 A.5): RSA key transport, no
	// encryption, HMAC-SHA256.
	TLS_RSA_WITH_NULL_SHA256 uint16 = 0x003b
)

// ConfigExt are the settings tlsx adds to Config.
type ConfigExt struct {
	// AcceptRenegotiation lets a TLS 1.2 server answer a renegotiation the
	// client starts. Off by default; a renegotiation the server itself
	// asked for (Conn.RequestRenegotiation) is always answered. Only secure
	// renegotiation (RFC 5746) is ever performed.
	AcceptRenegotiation bool

	// EncryptThenMAC offers (client) and accepts (server)
	// encrypt_then_mac (RFC 7366) for the TLS 1.2 CBC cipher suites.
	EncryptThenMAC bool
	// RequireEncryptThenMAC (implies EncryptThenMAC) refuses a CBC suite
	// without encrypt_then_mac: a client aborts if the server selects one
	// without echoing it, a server does not select one for a client that
	// did not offer it.
	RequireEncryptThenMAC bool

	// SignatureSchemes, if set, replaces the signature_algorithms list this
	// side sends (ClientHello, CertificateRequest) and accepts; the
	// signature_algorithms_cert list gets them added. It is how
	// rsa_pss_pss_* and the brainpool TLS 1.3 schemes are offered.
	SignatureSchemes []SignatureScheme

	// MaxFragmentLength is the client's max_fragment_length request (RFC
	// 6066 4): 1 to 4 for 512, 1024, 2048 or 4096 bytes; 0 asks nothing. A
	// server always honours a client's request.
	MaxFragmentLength uint8

	// RequestOCSPMulti makes a client also send status_request_v2 (RFC
	// 6961) asking for ocsp_multi, so a TLS 1.2 server can staple OCSP
	// responses for the whole chain.
	RequestOCSPMulti bool

	// TrustedCAKeys are sent by a client in trusted_ca_keys (RFC 6066 6).
	TrustedCAKeys []TrustedAuthority

	// CertificateAuthorities are DER distinguished names a client sends in
	// certificate_authorities (RFC 8446 4.2.4) when it offers TLS 1.3.
	CertificateAuthorities [][]byte

	// ServerSessionCache enables TLS 1.2 resumption by session ID on a
	// server (session tickets work as upstream).
	ServerSessionCache ServerSessionCache
	// ClientSessionIDs makes a TLS 1.2 client keep sessions the server
	// gave a session ID (and no ticket) in Config.ClientSessionCache and
	// offer the ID to resume.
	ClientSessionIDs bool

	// CipherSuitesTLS13, if set, are the TLS 1.3 cipher suites offered (a
	// client) or accepted in this preference order (a server); it allows
	// TLS_AES_128_CCM_SHA256, which is not offered by default.
	CipherSuitesTLS13 []uint16

	// StaticDHCertificate is a server's certificate with a static DH key
	// (PrivateKey *DHPrivateKey), used when the client selects
	// TLS_DH_RSA_WITH_AES_128_GCM_SHA256 (which Config.CipherSuites must
	// list; off by default).
	StaticDHCertificate *Certificate

	// AttributeCertificates are X.509 attribute certificates (DER) this
	// side sends in a SupplementalData message when the peer accepts them
	// (RFC 5878 x509_attr_cert, TLS 1.2 full handshakes); none by default.
	AttributeCertificates [][]byte
	// AcceptAttributeCertificates offers to receive the peer's attribute
	// certificates (ConnectionState().Ext.PeerAttributeCertificates).
	AcceptAttributeCertificates bool

	// AllowSHA1Signatures allows SHA-1 signatures (RSA PKCS #1 v1.5 and
	// ECDSA with SHA-1) in TLS 1.2 handshakes for this Config, as GODEBUG
	// tlssha1=1 does for the whole process: they are offered last, accepted
	// from the peer, and made when the peer prefers them or accepts nothing
	// else (also when a TLS 1.2 peer sends no signature_algorithms). It can
	// only allow: false follows GODEBUG. TLS 1.3 never uses SHA-1
	// signatures. ConnectionState().Ext.SHA1Signature reports their use.
	// CertificateRequestInfo.SupportsCertificate, which has no Config,
	// follows GODEBUG only.
	AllowSHA1Signatures bool

	// PSK configures pre-shared keys: TLS 1.2 PSK suites and TLS 1.3
	// external PSKs (x_psk.go). Nil: none.
	PSK *PSKConfig

	// RawPublicKeys configures raw public keys (RFC 7250; x_rpk.go). Nil:
	// X.509 only.
	RawPublicKeys *RawPublicKeyConfig

	// Observer, if set, is told about key updates and renegotiations. It
	// runs on the goroutine doing the work, with connection locks held: it
	// must return quickly and must not call methods of the Conn.
	Observer func(c *Conn, e Event)
}

// StateExt is the connection state tlsx adds to ConnectionState.
type StateExt struct {
	// EncryptThenMAC says encrypt_then_mac is in use (TLS 1.2 CBC suites).
	EncryptThenMAC bool
	// MaxFragmentLength is the negotiated record plaintext limit in bytes
	// (0: none, 16384).
	MaxFragmentLength int
	// SecureRenegotiation says the peer signalled RFC 5746 support in the
	// first handshake (TLS 1.2).
	SecureRenegotiation bool
	// Handshakes counts completed handshakes on the connection (1 plus
	// renegotiations).
	Handshakes int
	// KeyUpdatesSent and KeyUpdatesReceived count TLS 1.3 KeyUpdate
	// messages.
	KeyUpdatesSent, KeyUpdatesReceived uint64
	// LastKeyUpdateReceived is when the peer last updated its keys.
	LastKeyUpdateReceived time.Time
	// OCSPResponses are the stapled OCSP responses by position in
	// PeerCertificates (nil where none was stapled); OCSPResponse is
	// OCSPResponses[0].
	OCSPResponses [][]byte
	// SessionCreated is, on a TLS 1.2 server connection that resumed a
	// session (ticket or session ID), when the session's full handshake
	// was made (zero otherwise).
	SessionCreated time.Time
	// TrustedCAKeysAcknowledged says the server confirmed it chose its
	// certificate by the client's trusted_ca_keys (RFC 6066 6).
	TrustedCAKeysAcknowledged bool
	// PeerCertificateAuthorities are the DER names the peer sent in
	// certificate_authorities (a client's ClientHello, a server's
	// CertificateRequest).
	PeerCertificateAuthorities [][]byte
	// PeerAttributeCertificates are the attribute certificates the peer
	// sent (RFC 5878), unverified: the application checks them.
	PeerAttributeCertificates [][]byte
	// PSKIdentity is the pre-shared key identity the handshake used (nil
	// when none; empty but not nil for an empty TLS 1.2 identity);
	// PSKIdentityHint the TLS 1.2 server's hint a client got.
	PSKIdentity, PSKIdentityHint []byte
	// SHA1Signature says a TLS 1.2 handshake on the connection used a
	// SHA-1 signature, by either side (Config.Ext.AllowSHA1Signatures,
	// GODEBUG tlssha1=1).
	SHA1Signature bool
	// PeerRawPublicKey is the peer's raw public key (DER
	// SubjectPublicKeyInfo, RFC 7250) when it authenticated with one;
	// PeerCertificates is then empty. OwnRawPublicKey says this side sent
	// a raw public key.
	PeerRawPublicKey []byte
	OwnRawPublicKey  bool
}

// HelloExt is what tlsx reads from a ClientHello for ClientHelloInfo.
type HelloExt struct {
	// PSKModes are the psk_key_exchange_modes offered (0 psk_ke, 1
	// psk_dhe_ke).
	PSKModes []uint8
	// TrustedCAKeys is the client's trusted_ca_keys list, if sent.
	TrustedCAKeys []TrustedAuthority
	// CertificateAuthorities is the client's certificate_authorities.
	CertificateAuthorities [][]byte
	// EncryptThenMAC says the client offered encrypt_then_mac.
	EncryptThenMAC bool
	// MaxFragmentLength is the client's max_fragment_length code (0: none).
	MaxFragmentLength uint8
	// StatusRequestV2 says the client sent status_request_v2.
	StatusRequestV2 bool
	// SecureRenegotiation says the client signalled RFC 5746 support
	// (renegotiation_info or the SCSV).
	SecureRenegotiation bool
	// Renegotiation says the ClientHello starts a renegotiation.
	Renegotiation bool
}

// TrustedAuthority is one entry of trusted_ca_keys (RFC 6066 6).
type TrustedAuthority struct {
	// Type is 0 pre_agreed, 1 key_sha1_hash, 2 x509_name, 3 cert_sha1_hash.
	Type uint8
	// Data is the SHA-1 hash (types 1 and 3) or the DER distinguished name
	// (type 2); empty for pre_agreed.
	Data []byte
}

// Trusted authority identifier types (RFC 6066 6).
const (
	TrustedPreAgreed    uint8 = 0
	TrustedKeySHA1Hash  uint8 = 1
	TrustedX509Name     uint8 = 2
	TrustedCertSHA1Hash uint8 = 3
)

// ServerSessionCache stores TLS 1.2 sessions by session ID on a server.
// Implementations must be safe for concurrent use.
type ServerSessionCache interface {
	Get(sessionID string) (*SessionState, bool)
	Put(sessionID string, s *SessionState)
}

// EventKind names an Event.
type EventKind int

const (
	// EventKeyUpdateSent: this side sent a TLS 1.3 KeyUpdate; Requested
	// says it asked the peer to update too.
	EventKeyUpdateSent EventKind = iota + 1
	// EventKeyUpdateReceived: the peer's KeyUpdate was processed;
	// Requested says the peer asked this side to update.
	EventKeyUpdateReceived
	// EventHelloRequestSent: the server asked for a renegotiation.
	EventHelloRequestSent
	// EventRenegotiationStarted: a TLS 1.2 renegotiation began; ByPeer
	// says the peer started it.
	EventRenegotiationStarted
	// EventRenegotiated: a renegotiation completed; Resumed says it was
	// abbreviated (session resumption on the connection).
	EventRenegotiated
	// EventRenegotiationRefused: a renegotiation was refused before it
	// started (Err says why: ErrInsecureRenegotiation,
	// ErrRenegotiationNotAllowed, ErrRenegotiationVersionChange).
	EventRenegotiationRefused
	// EventRenegotiationFailed: a renegotiation handshake failed (Err);
	// the connection is unusable.
	EventRenegotiationFailed
)

// Event is a post-handshake event of a connection (ConfigExt.Observer).
type Event struct {
	Kind      EventKind
	Requested bool
	ByPeer    bool
	Resumed   bool
	// Version is the negotiated version; PeerVersion is the version the
	// peer asked for when it differs (ErrRenegotiationVersionChange).
	Version, PeerVersion uint16
	Err                  error
}

// Renegotiation errors.
var (
	// ErrInsecureRenegotiation: the peer did not signal secure
	// renegotiation (RFC 5746) or sent wrong verify data.
	ErrInsecureRenegotiation = errors.New("tlsx: peer does not support secure renegotiation (RFC 5746)")
	// ErrRenegotiationNotAllowed: renegotiation is not enabled.
	ErrRenegotiationNotAllowed = errors.New("tlsx: renegotiation not allowed by the configuration")
	// ErrRenegotiationVersionChange: the renegotiation asked for another
	// TLS version than the connection's.
	ErrRenegotiationVersionChange = errors.New("tlsx: renegotiation changes the TLS version")
	// ErrNotTLS12 and ErrNotTLS13 report a post-handshake operation for
	// the other version.
	ErrNotTLS12 = errors.New("tlsx: operation needs a TLS 1.2 connection")
	ErrNotTLS13 = errors.New("tlsx: operation needs a TLS 1.3 connection")
)

func (c *Conn) observe(e Event) {
	if c.config != nil && c.config.Ext.Observer != nil {
		if e.Version == 0 {
			e.Version = c.vers
		}
		c.config.Ext.Observer(c, e)
	}
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package tlsx is a fork of the crypto/tls package of the Go standard
// library (Go 1.27.1; BSD-3-Clause licence, see LICENSE, NOTICE and
// UPSTREAM.md) with TLS features crypto/tls does not have, for protocols
// that require them: industrial and utility profiles such as IEC 62351-3,
// device-management stacks that use pre-shared keys or raw public keys
// (for example oneM2M TS-0003), and meter or field-bus gateways. It is
// maintained independently and is not part of, or endorsed by, the Go
// project.
//
// # Why a copy of crypto/tls
//
// The other candidate was github.com/refraction-networking/utls (BSD-3).
// It exists to imitate other clients' ClientHellos; it is a fork of
// crypto/tls that trails upstream by releases and adds a large surface we
// do not need, and it implements none of the gaps below (no server
// renegotiation, no KeyUpdate API, no DHE, no encrypt_then_mac, no
// brainpool). Starting from it would mean two forks to follow. A copy of
// the standard library's package, rewritten only where it reaches into
// internal packages, keeps the diff against upstream small and is synced
// with scripts/sync-upstream.sh.
//
// # What tlsx adds
//
// With a zero Config.Ext and the default cipher suites and groups, tlsx
// behaves as crypto/tls of Go 1.27.1 (its upstream tests run, with the
// exceptions listed in UPSTREAM.md). The
// additions are opt-in:
//
//   - TLS 1.3 key update on demand: Conn.SendKeyUpdate (RFC 8446 4.6.3);
//     counts and times in ConnectionState().Ext, events through
//     Config.Ext.Observer. Config.Ext.MinKeyUpdateInterval accepts a
//     peer's timed updates on an idle connection, which crypto/tls drops
//     after 16.
//   - TLS 1.2 secure renegotiation (RFC 5746) in both roles: Conn.Renegotiate
//     (full, certificates validated again), Conn.Resume (abbreviated: the
//     session resumed on the connection for new keys),
//     Conn.RequestRenegotiation (server HelloRequest) and
//     Config.Ext.AcceptRenegotiation. Renegotiation is refused with a peer
//     that did not signal RFC 5746, keeps the version and the peer's leaf
//     certificate, runs on whichever goroutine holds the connection's read
//     side, and holds our writes while it runs.
//   - Cipher suites TLS_DHE_RSA_WITH_AES_128/256_GCM (RFC 5288) on the RFC
//     7919 groups only; TLS_ECDHE_*_WITH_AES_256_CBC_SHA384 (RFC 5289);
//     TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256
//     (Config.Ext.CipherSuitesTLS13; internal/ccm); the integrity-only
//     TLS 1.3 suites TLS_SHA256_SHA256 and TLS_SHA384_SHA384 (RFC 9150),
//     which give no confidentiality, and the TLS 1.2 TLS_RSA_WITH_NULL_SHA256
//     (Config.CipherSuites).
//   - encrypt_then_mac (RFC 7366) for every CBC suite
//     (Config.Ext.EncryptThenMAC, RequireEncryptThenMAC).
//   - Groups ffdhe2048/3072/4096 (RFC 7919; TLS 1.3 key shares and TLS 1.2
//     DHE) and brainpoolP256r1/P384r1/P512r1 (TLS 1.2 ECDHE, RFC 7027; TLS
//     1.3, RFC 8734), with ECDSA certificates and keys on the brainpool
//     curves, when listed in Config.CurvePreferences.
//   - Signature schemes rsa_pss_pss_sha256/384/512 and the brainpool TLS
//     1.3 schemes, offered through Config.Ext.SignatureSchemes; RSASSA-PSS
//     keys also as CA keys (fill pools with AppendCertsFromPEM).
//   - status_request_v2 (RFC 6961, ocsp_multi; Config.Ext.RequestOCSPMulti
//     and Certificate.ChainOCSPStaples) and per-certificate OCSP in TLS 1.3
//     (RFC 8446 4.4.2.1), both directions; ConnectionState().Ext.OCSPResponses.
//   - trusted_ca_keys (RFC 6066 6; Config.Ext.TrustedCAKeys,
//     TrustedAuthoritiesFor, TrustedAuthoritiesMatch) and
//     certificate_authorities in the ClientHello (RFC 8446 4.2.4;
//     Config.Ext.CertificateAuthorities).
//   - max_fragment_length (RFC 6066 4), honoured by servers and requested
//     by Config.Ext.MaxFragmentLength.
//   - TLS 1.2 resumption by session ID (Config.Ext.ServerSessionCache,
//     ClientSessionIDs).
//   - ClientHelloInfo.Ext: psk_key_exchange_modes, the extensions above,
//     and whether the hello starts a renegotiation.
//   - TLS authorization extensions (RFC 5878: client_authz, server_authz)
//     with SupplementalData (RFC 4680) carrying X.509 attribute
//     certificates, TLS 1.2 (Config.Ext.AttributeCertificates,
//     AcceptAttributeCertificates; ConnectionState().Ext.PeerAttributeCertificates).
//   - Pre-shared keys (x_psk.go; Config.Ext.PSK): the TLS 1.2 PSK, DHE_PSK
//     and ECDHE_PSK key exchanges (RFC 4279, RFC 5489) with the suites of
//     RFC 5487, 6655 (CCM, CCM_8), 7905 and 8442, a psk_identity_hint and
//     a server lookup callback, no certificate needed; TLS 1.3 external
//     PSKs (RFC 8446 4.2.11, "ext binder") with psk_dhe_ke and optionally
//     psk_ke. ConnectionState().Ext.PSKIdentity. The legacy HMAC-SHA-1
//     CBC suites of RFC 4279 and RFC 5489 are there for old devices, also
//     in TLS 1.0 and 1.1. TLS 1.2 PSK sessions are resumed with
//     PSKConfig.Resumption, bound to their key (x_psk_resume.go); TLS 1.3
//     external-PSK sessions are not.
//   - Raw public keys (x_rpk.go; RFC 7250; Config.Ext.RawPublicKeys) in
//     TLS 1.2 and 1.3, both directions, trusted through a verify callback
//     (pinning); ConnectionState().Ext.PeerRawPublicKey.
//   - Static Diffie-Hellman TLS_DH_RSA_WITH_AES_128_GCM_SHA256 (RFC 5288;
//     IEC 62351-4), off by default: DH certificates (X9.42 or PKCS #3
//     keys of 2048 bits or more), Config.Ext.StaticDHCertificate,
//     CreateStaticDHCertificate, GenerateStaticDHKey; an explicit client
//     public value only (no fixed_dh).
//
// # Constant time
//
// Finite field Diffie-Hellman uses internal/bigmod (Go's constant-time
// modular arithmetic, pure Go path). The brainpool curves are our own code
// (internal/brainpool): scalar multiplication, ECDH and ECDSA signing are
// constant time in the secret; verification and encodings handle public
// data only. AES-CCM (internal/ccm) uses crypto/aes and constant-time tag
// comparison.
//
// # GODEBUG and SHA-1
//
// The GODEBUG settings crypto/tls reads (tlssha1, tlsmlkem, tlssecpmlkem,
// tlsmaxrsasize) work as in crypto/tls: from the GODEBUG environment
// variable, else the build's defaults (go.mod go and godebug lines,
// //go:debug), else Go's defaults. They are read once, at first use; a
// later os.Setenv is not seen and runtime/metrics is not fed
// (GODEBUGValue and GODEBUGNonDefault report them instead). SHA-1
// signatures in TLS 1.2, off by default since Go 1.25, are allowed by
// GODEBUG tlssha1=1 or, for one Config, by Config.Ext.AllowSHA1Signatures.
//
// # Not implemented
//
// FIPS 140-3 mode, 0-RTT, and TLS 1.3 resumption of sessions made with an
// external PSK.
package tlsx

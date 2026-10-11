# Changelog

All notable changes to tlsx. Versions follow semantic versioning; before
v1.0.0, minor versions may change the API.

## v0.6.0 (2026-10-11)

- **New module path: `github.com/cB-Sigma/tlsx`.** The repository moved to
  the cB-Sigma organisation. Change imports from
  `github.com/cB-Abhinav-Gautam/tlsx` to `github.com/cB-Sigma/tlsx`; the
  code is the same as v0.5.0. Earlier versions stay available under the
  old path.

## v0.5.0 (2026-10-06)

- **TLS 1.3 resumption of external-PSK sessions** with
  `PSKConfig.Resumption` (and `TLS13`), in both roles (RFC 8446 2.2,
  4.6.1). After an external-PSK handshake the server sends a
  NewSessionTicket; the client resumes with the resumption PSK.
  - Sessions are bound to their external PSK as TLS 1.2 PSK sessions are:
    the client checks `Identity` and `Key`, the server calls `Lookup`, and
    a removed or changed key ends the resumption of its sessions (the
    client drops them from its cache).
  - The client offers the ticket first and its external identity second,
    each with its own binder (resumption and external binder keys), so a
    server that cannot resume the ticket takes the external PSK without
    another round trip. The external identity's obfuscated_ticket_age is
    0, also after a HelloRetryRequest. A tlsx server tries tickets before
    external identities. With Encrypted Client Hello only the ticket is
    offered, in the inner ClientHello.
  - psk_ke on resumption follows `AllowNoDHE` and `PreferNoDHE`;
    certificate sessions are still resumed with psk_dhe_ke only.
  - **Behaviour change:** a Config with `Resumption` and `TLS13` set now
    sends and uses TLS 1.3 tickets for external-PSK handshakes; before,
    `Resumption` covered TLS 1.2 only. Leave `Resumption` off to keep every
    PSK handshake a full one.
  - Tested Go to Go and against OpenSSL 3.6.4 (`s_client`/`s_server` with
    `-psk` and `-sess_out`/`-sess_in`) in both roles and both modes. BoGo
    results are unchanged (BoGo has no TLS 1.3 external-PSK tests).

## v0.4.0 (2026-09-28)

- **`Config.Ext.MinKeyUpdateInterval`** accepts a TLS 1.3 peer's timed
  KeyUpdates on an idle connection. Since Go 1.26.6, crypto/tls (and tlsx
  by default) closes a connection after more than 16 post-handshake
  messages in a row with no application data, KeyUpdates included, so a
  peer renewing its keys on a timer over an idle link (IEC 62351-3) was
  dropped at its 17th renewal. With the option, a KeyUpdate that arrives
  at least the interval after the last one that counted counts as
  progress; faster ones still count, so a flood is refused at the same
  limit. Zero, the default, is crypto/tls's behaviour; a test compares it
  with the toolchain's crypto/tls. Tested against OpenSSL 3.6.4 in both
  roles: 24 idle updates survive with the option, and the connection is
  dropped at the limit without it. BoGo results are unchanged, also with
  the option set in the shim (`TLSX_BOGO_MIN_KEY_UPDATE_INTERVAL=1h`,
  test by test); with `1ns` BoGo's TooManyKeyUpdates fails, as it should.

## v0.3.0 (2026-09-28)

- **BoGo.** BoringSSL's conformance suite runs against tlsx
  (`scripts/bogo.sh`, weekly in CI) with Go's shim, copied from Go 1.27.1
  and credited (NOTICE, UPSTREAM.md), and tlsx's own shim flags for PSK,
  renegotiation, KeyUpdate, session IDs and exporters. On BoringSSL
  v0.0.0-20260209204302-2a7ca5404e13: 3562 tests, 1562 pass, 5 expected
  failures (listed with reasons in bogo_config_tlsx.json and the README),
  1995 skipped; Go 1.27.1 passes 1333, and tlsx passes all of those.
- **Fixes found by BoGo.**
  - An RSASSA-PSS certificate key was accepted for RSA key exchange and
    for PKCS #1 v1.5, rsa_pss_rsae and TLS 1.0/1.1 signatures; it is now
    used only with rsa_pss_pss, in both roles. `IsRSAPSSKey` now follows
    the certificate's own SubjectPublicKeyInfo.
  - A renegotiation that changes the use of the extended master secret
    is refused (after a downgrade the connection still reported it).
  - A HelloRequest packed into the record of the server's Finished
    stalled the client until the next record; it is now refused with
    unexpected_message.
- **GODEBUG** settings work as in crypto/tls (tlssha1, tlsmlkem,
  tlssecpmlkem, tlsmaxrsasize): from the environment, else the build's
  defaults, read once at first use. `GODEBUGValue` and
  `GODEBUGNonDefault` report the values and non-default uses. The
  upstream tests that set GODEBUG now run.
- **`Config.Ext.AllowSHA1Signatures`** allows SHA-1 signatures in TLS 1.2
  for one Config, as GODEBUG tlssha1=1 does for the process;
  `ConnectionState().Ext.SHA1Signature` reports their use. Tested against
  OpenSSL in both roles.
- **Legacy PSK suites** for old devices: TLS_PSK_WITH_AES_128/256_CBC_SHA,
  TLS_DHE_PSK_WITH_AES_128/256_CBC_SHA and
  TLS_ECDHE_PSK_WITH_AES_128/256_CBC_SHA, also in TLS 1.0 and 1.1; used
  only when listed in Config.CipherSuites. A TLS 1.2 PSK identity may be
  empty.
- **TLS 1.2 PSK session resumption** with `PSKConfig.Resumption`, by
  ticket or session ID, bound to the PSK: a removed or changed key ends
  the resumption of its sessions. TLS 1.3 external-PSK sessions are still
  not resumed.

## v0.2.0 (2026-09-28)

- New package `revocation`: certificate revocation checking with CRLs
  (RFC 5280), for crypto/tls, tlsx and other stacks.
  - `Checker.VerifyConnection` fits crypto/tls's `Config.VerifyConnection`.
    `CheckChains` does the same for tlsx's, `VerifyPeerCertificate` fits
    crypto/tls, tlsx and pion/dtls, and `CheckChain` checks one chain.
  - One or more CRLs per CA, from files or HTTP(S) URLs. A CRL is used
    only if its issuer name matches, its signature verifies with the CA's
    key and it is within thisUpdate and nextUpdate. The leaf and every
    intermediate are checked.
  - Fail-closed by default; fail-open only when set per CA. CAs without a
    CRL are not checked and are listed as not configured.
  - Background refresh, periodic and ahead of nextUpdate, with back-off.
    The last good CRL is kept, and a lower CRL number is refused as a
    rollback. HTTP fetches have a timeout and a size limit.
  - `Status` per CRL, and an event hook for metrics and logging.
  - CRLs partitioned by issuing distribution point URI are supported.
    Not supported: OCSP (`Config.Extra` is the extension point), delta
    CRLs, indirect CRLs, CRLs partitioned by reason.
  - Tested with CRLs from crypto/x509 and one from `openssl ca -gencrl`,
    and in TLS 1.2 and 1.3 handshakes with crypto/tls and tlsx servers.
- CI: actions/checkout v7, actions/setup-go v7 and actions/cache v6
  (Node.js 24).

## v0.1.0 (2026-09-28)

First standalone release. tlsx was developed inside SigmaM2M and is now a
module of its own, `github.com/cB-Abhinav-Gautam/tlsx`.

- Upstream base: Go 1.27.1 (crypto/tls, crypto/internal/fips140/tls12,
  tls13 and bigmod). Requires Go 1.27.1 or later.
  - From Go 1.27: ML-DSA signature schemes (via `crypto/mldsa`), the
    ML-KEM-1024 key exchange (`MLKEM1024`), the new curve preference logic,
    and re-recorded test handshakes.
  - From Go 1.26.6 and 1.27: KeyUpdate messages no longer count as
    progress on a connection. A peer closes the connection after more than
    16 consecutive post-handshake messages with no application data between
    them; this affects callers of `Conn.SendKeyUpdate` on idle connections.
  - From Go 1.26.6: pre_shared_key is no longer sent in the outer
    ClientHello of Encrypted Client Hello. tlsx does not offer an external
    PSK together with ECH; new tests check both.
- tlsx additions: pre-shared keys (TLS 1.2 PSK suites and TLS 1.3 external
  PSKs), raw public keys, TLS 1.2 renegotiation and session-ID resumption,
  TLS 1.3 KeyUpdate on demand, DHE, CCM, integrity-only and NULL suites,
  static DH, encrypt_then_mac, the RFC 7919 and brainpool groups,
  rsa_pss_pss signatures, status_request_v2, trusted_ca_keys,
  certificate_authorities, max_fragment_length and the RFC 5878
  authorization extensions. See doc.go.
- Interoperability tests against OpenSSL 3 and, for raw public keys, GnuTLS.
- Provenance: every file is classified in PROVENANCE.md
  (`scripts/provenance.sh`). Go's headers are kept, and Go-derived passages
  in tlsx's own files are credited (NOTICE).
- The repository carries Go's own history of the files it derives from
  (`scripts/filter-upstream.sh`), so `git blame` names Go's authors.
  `scripts/sync-upstream.sh` merges new Go releases as git merges of that
  history. A weekly workflow runs the sync on a scratch branch and reports
  the result and test results.

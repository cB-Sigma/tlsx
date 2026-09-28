# Changelog

All notable changes to tlsx. Versions follow semantic versioning; before
v1.0.0, minor versions may change the API.

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

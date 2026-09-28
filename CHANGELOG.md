# Changelog

All notable changes to tlsx. Versions follow semantic versioning; before
v1.0.0, minor versions may change the API.

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
- `scripts/sync-upstream.sh` merges new Go releases. A weekly workflow
  reports new releases with a dry run and test results.

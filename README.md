# tlsx

tlsx is a fork of the `crypto/tls` package of the Go standard library,
extended with TLS features that crypto/tls does not have. Industrial,
utility and device-management protocols need these features.

> **Attribution.** tlsx is a fork of the crypto/tls package of the Go
> project, Copyright The Go Authors, under the BSD-3-Clause licence.
> Google's patent grant is in [PATENTS](PATENTS). Most of the code in this
> repository is Go's. tlsx is maintained independently. It is not part of
> the Go project and is not affiliated with Go or Google, and neither has
> reviewed or endorsed it. [NOTICE](NOTICE) says what is Go's and what is
> ours; [PROVENANCE.md](PROVENANCE.md) does so file by file.

```
go get github.com/cB-Abhinav-Gautam/tlsx
```

Requires Go 1.27.1 or later. The current upstream base is Go 1.27.1.

## Why tlsx exists

Go's crypto/tls is deliberately small. It implements modern TLS for the
web very well, and leaves out features the web does not need. Many
industrial, utility and IoT protocols do need them:
- Their standards require TLS features that crypto/tls lacks, for example
  IEC 62351-3 (DNP3, IEC 60870-5-104, IEC 61850) and oneM2M TS-0003.
- Their devices are too small or too numerous for certificates, so they
  use pre-shared keys or raw public keys.

The Go project does not plan them for crypto/tls; pre-shared-key support,
for example, is the request
[golang/go#6379](https://github.com/golang/go/issues/6379). So a Go
program that talks to such devices has three choices: cgo and OpenSSL, a
different language, or a fork.

tlsx is that fork, kept as close to Go as possible:
- It carries Go's own code and git history.
- Its changes are small, marked `// tlsx` and opt-in.
- It is merged with every Go release, so Go's security fixes arrive as
  Go's own commits.
- It is pure Go, with no cgo.

## At a glance

| | crypto/tls (Go 1.27) | tlsx |
|---|---|---|
| TLS 1.2 / 1.3, ECDHE, modern AEADs, ECH, QUIC, ML-KEM | yes | yes (Go's code) |
| Pre-shared keys, TLS 1.2 PSK suites and TLS 1.3 external PSK | no | yes, with TLS 1.2 PSK session resumption |
| Raw public keys (RFC 7250) | no | yes |
| TLS 1.2 renegotiation | client may accept only | client and server, RFC 5746 required |
| TLS 1.3 key update | answers the peer's | also sends on demand |
| Finite-field DHE (RFC 7919 groups) | no | yes |
| AES-CCM and CCM_8 suites | no | yes |
| Brainpool curves | no | yes |
| encrypt_then_mac (RFC 7366) | no | yes |
| Integrity-only and NULL suites | no | yes, opt-in (no confidentiality) |
| status_request_v2, trusted_ca_keys, max_fragment_length | no | yes |
| Certificate revocation (CRLs) | no built-in check | CRL package `revocation`, opt-in; works with crypto/tls too |
| SHA-1 signatures in TLS 1.2 | GODEBUG tlssha1=1 | GODEBUG, or per Config (`Ext.AllowSHA1Signatures`) |
| GODEBUG settings | yes | yes, read once at first use |
| FIPS 140-3 mode | yes | no |
| BoringSSL's BoGo conformance suite | runs in Go's tree | runs weekly, with flags for tlsx's features |

## When not to use it

If crypto/tls already does what you need, use crypto/tls. It is maintained
by the Go team and has a smaller surface. Some of tlsx's additions exist
only because protocol standards demand them and weaken security when
misused:
- the integrity-only and NULL suites give no confidentiality;
- static DH and renegotiation have known pitfalls.
All of them are off unless you turn them on. Turn on only what your
protocol requires.

**If you need FIPS 140-3, use crypto/tls in FIPS mode, not tlsx.**
- Go's FIPS 140-3 mode rests on the Go Cryptographic Module. The module
  is validated as it ships inside the standard library.
- A fork outside the standard library can't use its internal packages.
  tlsx calls the public crypto packages instead and carries its own copy
  of the TLS key derivation, so tlsx is not FIPS 140-3 validated.
- Several of tlsx's additions are not FIPS-approved algorithms anyway.
- GODEBUG settings work as in crypto/tls (see below), but tlsx reads
  them itself, so they do not change the FIPS 140-3 status either.

## What it adds over crypto/tls

With a zero `Config.Ext` and the default cipher suites and groups, tlsx
behaves like crypto/tls of its base Go release. Every addition is opt-in:

- **Pre-shared keys.**
  - TLS 1.2 PSK, DHE_PSK and ECDHE_PSK key exchanges (RFC 4279, RFC 5489) with the suites of RFC 5487, 6655, 7905 and 8442.
  - For old devices, the legacy HMAC-SHA-1 CBC suites of RFC 4279 and RFC 5489 (`TLS_PSK_WITH_AES_128_CBC_SHA` and the like), also in TLS 1.0 and 1.1.
  - TLS 1.2 PSK session resumption (`PSKConfig.Resumption`), by ticket or session ID, bound to the PSK: a removed or changed key ends it.
  - TLS 1.3 external PSKs (RFC 8446 4.2.11) with psk_dhe_ke and, optionally, psk_ke.
  - No certificate needed.
- **Raw public keys** (RFC 7250). TLS 1.2 and 1.3, both directions, trusted through a pinning callback.
- **TLS 1.2 secure renegotiation** (RFC 5746) in both roles, and TLS 1.2 resumption by session ID.
- **TLS 1.3 KeyUpdate on demand** (`Conn.SendKeyUpdate`).
- **Extra cipher suites.**
  - TLS_DHE_RSA_WITH_AES_128/256_GCM on the RFC 7919 groups.
  - ECDHE CBC-SHA384 (RFC 5289).
  - TLS_AES_128_CCM_SHA256 and TLS_AES_128_CCM_8_SHA256.
  - The integrity-only TLS 1.3 suites of RFC 9150. They provide no confidentiality.
  - TLS_RSA_WITH_NULL_SHA256.
  - Static DH TLS_DH_RSA_WITH_AES_128_GCM_SHA256.
- **encrypt_then_mac** (RFC 7366) for CBC suites.
- **More groups.**
  - ffdhe2048/3072/4096 (RFC 7919).
  - brainpoolP256r1/P384r1/P512r1 (RFC 7027, RFC 8734), with brainpool ECDSA certificates.
- **More signature schemes.** rsa_pss_pss_* and RSASSA-PSS CA keys.
- **More extensions.**
  - status_request_v2 (RFC 6961) and per-certificate OCSP in TLS 1.3.
  - trusted_ca_keys (RFC 6066).
  - certificate_authorities in the ClientHello.
  - max_fragment_length (RFC 6066).
  - The RFC 5878 authorization extensions, with RFC 4680 SupplementalData.

- **SHA-1 signatures in TLS 1.2**, off by default as in Go 1.25 and
  later: GODEBUG `tlssha1=1` for the process, or
  `Config.Ext.AllowSHA1Signatures` for one Config (it can only allow;
  `ConnectionState().Ext.SHA1Signature` reports their use).
- **GODEBUG.** The settings crypto/tls reads (`tlssha1`, `tlsmlkem`,
  `tlssecpmlkem`, `tlsmaxrsasize`) come from the GODEBUG environment
  variable, else from the build's defaults (the go.mod `go` and `godebug`
  lines, `//go:debug` directives), else Go's defaults. tlsx reads them
  once, at first use: a later `os.Setenv("GODEBUG", ...)` is not seen,
  and runtime/metrics' `/godebug/non-default-behavior/...` counters are
  not fed; `GODEBUGValue` and `GODEBUGNonDefault` report the values and
  counts instead.

The package documentation ([doc.go](doc.go)) has the details and the API.

Things tlsx does not do:
- FIPS 140-3 mode;
- TLS 1.3 resumption of sessions made with an external PSK;
- 0-RTT (early data), as crypto/tls.

Example uses: IEC 62351-3 profiles for DNP3, IEC 60870-5-104 and
IEC 61850 MMS; oneM2M TS-0003 pre-shared-key and raw-public-key security;
wireless M-Bus / OMS gateways.

## Usage

tlsx has the same API as crypto/tls. Change the import and set the fields
of `Config.Ext` that you need:

```go
import "github.com/cB-Abhinav-Gautam/tlsx"

// Client: TLS 1.3 with an external pre-shared key, no certificates.
cfg := &tlsx.Config{
	ServerName: "gateway.example",
	MinVersion: tlsx.VersionTLS13,
	Ext: tlsx.ConfigExt{PSK: &tlsx.PSKConfig{
		TLS13:    true,
		Identity: []byte("device-42"),
		Key:      key, // 32 bytes
	}},
}
conn, err := tlsx.Dial("tcp", "gateway.example:5684", cfg)
```

[x_example_test.go](x_example_test.go) has runnable examples for pre-shared
keys and raw public keys.

tlsx's `Config` and `Conn` are distinct types from crypto/tls's. Code that
takes a `*tls.Config`, such as `net/http`, needs an adapter, for example a
`net.Listener` that returns tlsx connections.

## Certificate revocation

Neither crypto/tls nor tlsx checks whether a certificate was revoked;
both leave it to the `VerifyConnection` hook. The package
[`revocation`](revocation/doc.go) is such a hook, for servers that
authenticate client certificates (devices, gateways, operators) and for
clients. It checks the peer's verified chains against certificate
revocation lists (CRLs, RFC 5280), and works with crypto/tls as well as
tlsx:

```go
import "github.com/cB-Abhinav-Gautam/tlsx/revocation"

chk, err := revocation.New(revocation.Config{
	Sources: []revocation.Source{
		{Issuer: deviceCA, URL: "http://pki.example/device-ca.crl"},
		{Issuer: rootCA, File: "/etc/pki/root.crl"},
	},
})
if err != nil { ... }
defer chk.Close()

// crypto/tls
cfg := &tls.Config{
	ClientAuth:       tls.RequireAndVerifyClientCert,
	ClientCAs:        pool,
	VerifyConnection: chk.VerifyConnection,
}

// tlsx
xcfg := &tlsx.Config{
	ClientAuth: tlsx.RequireAndVerifyClientCert,
	ClientCAs:  pool,
	VerifyConnection: func(cs tlsx.ConnectionState) error {
		return chk.CheckChains(cs.VerifiedChains)
	},
}
```

`VerifyPeerCertificate` fits the hook of the same name in crypto/tls, tlsx
and pion/dtls, and `CheckChain` checks a single chain.

- **What is checked.** The leaf and every intermediate, each against the
  CRL of its issuer. A CRL is used only if its issuer name matches the CA,
  its signature verifies with the CA's key, and it is within its
  thisUpdate and nextUpdate times. Every verified chain must pass.
- **Failure policy.** Fail-closed is the default for every CA that has a
  CRL configured: if the CRL is missing, unreadable, badly signed or past
  its nextUpdate, the certificate is refused with a clear error.
  Fail-open must be chosen per CA; it still refuses certificates listed
  in the last good CRL. A CA without a configured CRL is not checked, and
  `Status` lists it as "not configured".
- **Refresh.** CRLs come from files or HTTP(S) URLs. They are refetched
  periodically and ahead of nextUpdate, with back-off on failure. HTTP
  fetches have a timeout and a size limit. The last good CRL is kept, and
  a CRL with a lower CRL number is refused as a rollback.
- **Status.** `Status` reports, per CRL, the last fetch, thisUpdate,
  nextUpdate, CRL number, number of entries, last error and whether it is
  stale. `Config.OnEvent` feeds metrics or logs.
- **Limits.**
  - No OCSP yet; `Config.Extra` is the extension point for it.
  - No delta CRLs: a delta CRL is refused rather than taken for a full one.
  - No indirect CRLs and no CRLs partitioned by reason. CRLs partitioned
    by distribution point URI are supported.
  - Unknown critical CRL extensions make a CRL unusable.
  - The rollback check is in memory and does not survive a restart.

The package documentation ([revocation/doc.go](revocation/doc.go)) has the
details; [revocation/example_test.go](revocation/example_test.go) has the
examples.

## How it tracks upstream

tlsx carries Go's files with small, marked changes, on top of Go's own
history:
- The repository's history starts with every Go commit that touched the
  files tlsx carries, rewritten to tlsx's layout by `git filter-repo` and
  otherwise unchanged. `git blame` names the Go author and commit of each
  Go line; the ID map is in `docs/upstream-commit-map.txt`.
- The package rename and import rewrites are separate `mechanical:`
  commits, listed in `.git-blame-ignore-revs`. GitHub's blame view reads
  that file; locally, run
  `git config blame.ignoreRevsFile .git-blame-ignore-revs` once, and
  rewritten lines blame to the Go commits that wrote them.
- A new Go release comes in as a git merge of its filtered history
  (`scripts/sync-upstream.sh`), followed by a mechanical rewrite commit.
  Conflicts appear only where upstream changed lines that tlsx changed.
- A weekly GitHub workflow checks for a new stable Go release, runs the
  sync on a scratch branch and opens an issue with the result.
- Go's own crypto/tls tests run in this repository, apart from a documented
  list of skips.

[UPSTREAM.md](UPSTREAM.md) describes the procedure and each rewrite.

Security fixes in Go's crypto/tls reach tlsx only through a sync. If you
depend on tlsx, follow its releases as you would follow Go's.

## Verification

Features were checked against implementations other than Go where one
exists. The interoperability tests run in CI (Ubuntu's OpenSSL and GnuTLS)
and locally when the tools are installed; the table records the versions of
the last local run.

**Tested against another implementation:**

| Feature | Checked against | Directions |
|---|---|---|
| TLS 1.3 KeyUpdate | OpenSSL 3.6.4 | Go client ↔ s_server, s_client ↔ Go server |
| TLS 1.2 renegotiation (RFC 5746), incl. HelloRequest and refusals | OpenSSL 3.6.4 | both roles |
| DHE_RSA GCM suites on ffdhe2048; refusal of custom groups | OpenSSL 3.6.4 | both roles |
| ffdhe2048 key share in TLS 1.3 | OpenSSL 3.6.4 | both roles |
| TLS_AES_128_CCM_SHA256 | OpenSSL 3.6.4 | both roles |
| TLS_AES_128_CCM_8_SHA256, TLS_SHA256_SHA256, TLS_SHA384_SHA384 | OpenSSL 3.6.4 | both roles |
| encrypt_then_mac with three CBC suites | OpenSSL 3.6.4 | both roles |
| rsa_pss_pss_* signatures, TLS 1.2 and 1.3 | OpenSSL 3.6.4 | both roles |
| RSASSA-PSS CA key in a chain | OpenSSL 3.6.4 | Go client only |
| brainpool groups and ECDSA certificates, TLS 1.2 and 1.3 | OpenSSL 3.6.4 | both roles |
| brainpool curve parameters, ECDH, ECDSA both ways, certificates and CSRs | OpenSSL 3.6.4 (command line) | n/a |
| max_fragment_length | OpenSSL 3.6.4 | both roles |
| TLS 1.2 session-ID resumption | OpenSSL 3.6.4 | both roles |
| OCSP stapling of the chain in TLS 1.3, certificate_authorities | OpenSSL 3.6.4 | both roles |
| TLS_RSA_WITH_NULL_SHA256 | OpenSSL 3.6.4 | both roles |
| TLS 1.2 PSK: 21 suites (PSK, DHE_PSK, ECDHE_PSK; CBC with SHA-1/256/384, GCM, CCM, CCM_8, ChaCha20), unknown identity | OpenSSL 3.6.4 | both roles |
| Legacy SHA-1 CBC PSK suites in TLS 1.0 and 1.1 (three suites) | OpenSSL 3.6.4 | both roles |
| SHA-1 signatures in TLS 1.2 (`AllowSHA1Signatures`), client certificates, refusal without it | OpenSSL 3.6.4 (security level 0, RSA+SHA1 only) | both roles |
| TLS 1.3 external PSK, psk_dhe_ke and psk_ke | OpenSSL 3.6.4 | both roles |
| Raw public keys, TLS 1.2 and 1.3, pinning refusals | OpenSSL 3.6.4 and GnuTLS 3.8.13 | both roles, both implementations |
| AES-CCM (internal/ccm) | RFC 3610 vectors; one value from Python cryptography | n/a |
| brainpool ECDH | RFC 7027 Appendix A vectors | n/a |
| CRL parsing and checking (`revocation`), incl. CRL number and reason | OpenSSL 3.6.4 (`openssl ca -gencrl`) | n/a |

**Tested only by tlsx's own tests (Go client against Go server):**

- **status_request_v2** (RFC 6961, ocsp_multi). OpenSSL and GnuTLS don't implement it.
- **trusted_ca_keys** (RFC 6066 6). OpenSSL and GnuTLS don't implement it.
- **RFC 5878 authorization extensions and SupplementalData.** No maintained implementation is known.
- **Static DH (TLS_DH_RSA_WITH_AES_128_GCM_SHA256).** Current OpenSSL and GnuTLS don't support static DH suites.
- **ffdhe3072/4096 and brainpoolP384r1/P512r1 in handshakes.** Only ffdhe2048 and brainpoolP256r1 go through a handshake with OpenSSL. The curve arithmetic of all three brainpool curves is cross-checked with OpenSSL.
- **`ClientHelloInfo.Ext`** and the event observer.
- **External PSK with Encrypted Client Hello.** The identity is not sent.
- **TLS 1.2 PSK session resumption** (tickets and session IDs, refusal
  after a key is removed or changed); BoGo's PSK cipher-suite tests also
  resume against BoringSSL's runner.
- **GODEBUG** sources and precedence (environment, build defaults), and
  `tlssha1=1` end to end.
- **The `revocation` package's refresh, HTTP source, failure policy and
  handshakes** (crypto/tls and tlsx servers, TLS 1.2 and 1.3), with CRLs
  made by crypto/x509. Only CRL parsing is checked against OpenSSL.

**Upstream behaviour.** Go's own crypto/tls tests run here with small
adjustments, listed in UPSTREAM.md:
- 5 tests skip at run time, each with its reason (`go test -v`): 2 that
  use the external network and 3 recorded renegotiation flights (tlsx's
  renegotiation ClientHello differs). The tests that set GODEBUG run,
  since tlsx honours GODEBUG. TestBogoSuite skips unless asked (below);
- the FIPS 140 variant in tls_test.go is replaced by a skip (no FIPS mode);
- tls_test.go sets `Config.Ext` in its Config.Clone test and leaves tlsx's
  extra cipher suites out of its checks of upstream's suite lists.

They include the handshakes recorded against OpenSSL in `testdata/`. They
exercise the upstream code paths; they say nothing about tlsx's additions.

**Not done.**
- No independent security audit.
- No fuzzing beyond Go's own tests.

### BoGo

BoGo is BoringSSL's TLS conformance suite: a test runner, written in Go,
that drives a "shim" through thousands of handshakes, including broken
and hostile ones. tlsx carries Go's shim (`bogo_shim_test.go`, a copy of
Go 1.27.1's, see UPSTREAM.md) and runs it with `scripts/bogo.sh`, weekly
in CI (`.github/workflows/bogo.yml`) and on demand. BoringSSL is
downloaded at the revision Go pins (`v0.0.0-20260209204302-2a7ca5404e13`)
through the Go module proxy; nothing of it is in this repository.

Results on that revision (3562 tests; "skipped" are tests whose shim
flags neither Go's shim nor tlsx's implement, and those Go's
`bogo_config.json` disables):

| Shim | Passed | Failed | Skipped |
|---|---|---|---|
| Go 1.27.1 crypto/tls, Go's shim | 1333 | 0 | 2229 |
| tlsx, Go's shim flags only (commit e2f0717, before tlsx's flags) | 1333 (the same tests) | 0 | 2229 |
| tlsx, with its own flags | 1562 | 5, all expected | 1995 |

- **Differences from Go, and what they found.** The first run of tlsx
  with Go's shim failed 7 tests that Go passes: tlsx used an RSASSA-PSS
  certificate key for RSA key exchange and for PKCS #1 v1.5, rsa_pss_rsae
  and TLS 1.0/1.1 signatures (CertificateCipherMismatch-PSS,
  RejectPSSKeyType-*). Fixed; since then every test Go passes, tlsx passes too.
- **tlsx's flags** (`x_bogo_test.go`) map BoGo's shim flags onto tlsx's
  features: `-psk` and `-psk-identity` (TLS 1.2 PSK suites, resumption),
  `-renegotiate-freely`, `-renegotiate-once`,
  `-expect-total-renegotiations`, `-expect-secure-renegotiation`,
  `-expect-no-secure-renegotiation` (client renegotiation), `-key-update`
  (sending KeyUpdate), `-no-ticket` (session-ID resumption) and the
  exporter flags the cipher-suite tests need. They bring 234 more tests
  into the run (229 pass, 5 are the expected failures below): the
  cipher-suite client and server tests of every version (114), PSK (67),
  renegotiation and HelloRequest (30), exporters (17), -no-ticket (4)
  and KeyUpdate (2). They found three more bugs, now fixed: a renegotiation
  could change the use of the extended master secret, a HelloRequest
  packed with the server's Finished stalled the client, and the legacy
  SHA-1 PSK suites, empty TLS 1.2 identities and PSK session resumption
  were missing.
- **Expected failures** (`bogo_config_tlsx.json`; they run, and one that
  starts to pass fails the test):
  - Renegotiate-Client, Renegotiate-Client-TLS12: the runner takes any
    session ID in a renegotiation ClientHello for an offer to resume;
    tlsx, like crypto/tls, always sends a random session ID and offers no
    session when renegotiating.
  - Renegotiate-Client-NoExt-Allowed: tlsx renegotiates only with peers
    that support secure renegotiation (RFC 5746).
  - Renegotiate-Client-Once-2: tlsx, like crypto/tls, refuses a second
    renegotiation with a warning-level no_renegotiation alert (RFC 5246
    7.2.2); the runner ignores warnings and expects BoringSSL's fatal
    alert.
  - ExportKeyingMaterial-Server-HalfRTT-TLS-TLS13: 0-RTT is not
    implemented (nor in crypto/tls); Go's shim accepts `-enable-early-data`
    without acting on it.
- **SHA-1.** Go's `bogo_config.json` disables BoGo's 23 SHA-1 signature
  tests. Run with them enabled, Go and tlsx agree test by test: 19 fail
  and 4 pass by default, all 23 pass with GODEBUG `tlssha1=1`.
- **What BoGo cannot cover**, because BoringSSL does not implement it:
  TLS 1.3 external PSKs, finite-field DHE (DHE_RSA, DHE_PSK), AES-CCM,
  raw public keys, max_fragment_length, encrypt_then_mac, brainpool,
  ffdhe groups, status_request_v2, trusted_ca_keys, the NULL and
  integrity-only suites, and server-side renegotiation (BoGo only checks
  that a server refuses it). `-max-send-fragment` has no tlsx
  counterpart (tlsx negotiates max_fragment_length instead). These rely on
  the interoperability tests above.

## Licence

BSD-3-Clause, the same licence as Go's; see [LICENSE](LICENSE),
[PATENTS](PATENTS) and [NOTICE](NOTICE). Contributions are accepted under
the same licence ([CONTRIBUTING.md](CONTRIBUTING.md)). To report a
vulnerability, see [SECURITY.md](SECURITY.md).

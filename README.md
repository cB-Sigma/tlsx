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

## What it adds over crypto/tls

With a zero `Config.Ext` and the default cipher suites and groups, tlsx
behaves like crypto/tls of its base Go release. Every addition is opt-in:

- **Pre-shared keys.**
  - TLS 1.2 PSK, DHE_PSK and ECDHE_PSK key exchanges (RFC 4279, RFC 5489) with the suites of RFC 5487, 6655, 7905 and 8442.
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

The package documentation ([doc.go](doc.go)) has the details and the API.
Things tlsx does not do:
- FIPS 140-3 mode;
- GODEBUG settings, which stay at their defaults;
- SHA-1 signatures in TLS 1.2 handshakes.

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
| TLS 1.2 PSK: 15 suites (PSK, DHE_PSK, ECDHE_PSK; CBC, GCM, CCM, CCM_8, ChaCha20), unknown identity | OpenSSL 3.6.4 | both roles |
| TLS 1.3 external PSK, psk_dhe_ke and psk_ke | OpenSSL 3.6.4 | both roles |
| Raw public keys, TLS 1.2 and 1.3, pinning refusals | OpenSSL 3.6.4 and GnuTLS 3.8.13 | both roles, both implementations |
| AES-CCM (internal/ccm) | RFC 3610 vectors; one value from Python cryptography | n/a |
| brainpool ECDH | RFC 7027 Appendix A vectors | n/a |

**Tested only by tlsx's own tests (Go client against Go server):**

- **status_request_v2** (RFC 6961, ocsp_multi). OpenSSL and GnuTLS don't implement it.
- **trusted_ca_keys** (RFC 6066 6). OpenSSL and GnuTLS don't implement it.
- **RFC 5878 authorization extensions and SupplementalData.** No maintained implementation is known.
- **Static DH (TLS_DH_RSA_WITH_AES_128_GCM_SHA256).** Current OpenSSL and GnuTLS don't support static DH suites.
- **ffdhe3072/4096 and brainpoolP384r1/P512r1 in handshakes.** Only ffdhe2048 and brainpoolP256r1 go through a handshake with OpenSSL. The curve arithmetic of all three brainpool curves is cross-checked with OpenSSL.
- **`ClientHelloInfo.Ext`** and the event observer.
- **External PSK with Encrypted Client Hello.** The identity is not sent.

**Upstream behaviour.** Go's own crypto/tls tests run here with small
adjustments, listed in UPSTREAM.md:
- 13 subtests skip at run time, each with its reason (`go test -v`): 8
  that set GODEBUG (tlsx keeps the settings at their defaults), 2 that use
  the external network, and 3 recorded renegotiation flights (tlsx's
  renegotiation ClientHello differs);
- the FIPS 140 variant in tls_test.go is replaced by a skip (no FIPS mode);
- handshake_test.go's hooks for the BoGo shim are removed (the shim is not
  carried);
- tls_test.go sets `Config.Ext` in its Config.Clone test and leaves tlsx's
  extra cipher suites out of its checks of upstream's suite lists.


They include the handshakes recorded against OpenSSL in `testdata/`. They
exercise the upstream code paths; they say nothing about tlsx's additions.

**Not done.**
- No independent security audit.
- No fuzzing beyond Go's own tests.
- No run of BoringSSL's BoGo suite (see below).

### BoGo

BoGo is BoringSSL's TLS conformance suite. Go's crypto/tls runs it through
`bogo_shim_test.go`, which tlsx doesn't carry. Running it against tlsx
would take:
- carrying `bogo_shim_test.go` and `bogo_config.json` with the package
  renamed;
- a checkout of BoringSSL at the revision Go pins (Go's test fetches it
  through the module proxy);
- running `go test -run TestBogoSuite` with the shim;
- keeping upstream's `bogo_config.json` list of expected failures, plus a
  tlsx list for behaviour tlsx changes on purpose, such as renegotiation.

The shim would also need flags for tlsx's features before BoGo's PSK,
renegotiation and KeyUpdate tests say anything about them. This is planned,
not done.

## Licence

BSD-3-Clause, the same licence as Go's; see [LICENSE](LICENSE),
[PATENTS](PATENTS) and [NOTICE](NOTICE). Contributions are accepted under
the same licence ([CONTRIBUTING.md](CONTRIBUTING.md)). To report a
vulnerability, see [SECURITY.md](SECURITY.md).

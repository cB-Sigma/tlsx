# Tracking upstream

Base: go1.27.1 (src/crypto/tls, crypto/internal/fips140/tls12, tls13 and bigmod of the Go 1.27.1 release)

tlsx is a fork of Go's `crypto/tls`. Go's licence (BSD-3-Clause) is in
[LICENSE](LICENSE) with Go's [PATENTS](PATENTS) grant; what is Go's and
what is ours is in [NOTICE](NOTICE) and, file by file, in
[PROVENANCE.md](PROVENANCE.md).

## How the copy is made

`scripts/upstream-lib.sh` holds the rules; the sync and provenance scripts
both use them.

- **Files.** Every file of `src/crypto/tls` except:
  - the BoGo shim (`bogo_shim_*`);
  - the FIPS 140 tests (`fips140_test.go`);
  - `link_test.go`, `defaults_boring.go`, `generate_cert.go` and `example_test.go`;
  - `certificates_generator_test.go`.

  `certificates_test.go`, which the generator writes, is carried as is.
  `testdata/` is carried as is. Three packages of `crypto/internal/fips140`
  are carried too:
  - `tls12` becomes `internal/tls12`, using `crypto/hmac` instead of the FIPS module;
  - `tls13` becomes `internal/tls13`, using `crypto/hkdf`;
  - `bigmod` becomes `internal/bigmod`, the pure Go `nat_noasm.go` code path.
- **Mechanical rewrites.** The sync script repeats these:
  - package `tls` becomes `tlsx`;
  - `//go:linkname` and `//go:build` lines are removed;
  - `internal/godebug`, `crypto/tls/internal/fips140tls` and `internal/byteorder` are replaced by the stand-ins in `upstream_shims.go`. GODEBUG settings stay at their defaults, and FIPS mode is never required;
  - `internal/cpu` becomes `golang.org/x/sys/cpu`;
  - in tests, `crypto/internal/boring`, `crypto/internal/cryptotest` and `internal/testenv` become the small stand-ins under `internal/`, and `crypto/internal/rand` becomes the stand-in in `upstream_shims_test.go`;
  - in bigmod, the internal `byteorder` becomes `encoding/binary`.
- **Changes that are not mechanical.**
  - BoringCrypto and the FIPS GCM constructors are replaced by `crypto/cipher` (`gcm_tls.go`).
  - The FIPS approval bookkeeping in `tls12` is removed.
- **tlsx's own code.**
  - It lives in files named `x_*.go` and in `internal/tls13/x_external.go`.
  - The upstream files carry small hooks marked `// tlsx`; `grep -n '// tlsx' *.go` lists them.
  - Each upstream file with changes has a notice line under Go's header.
- **Upstream tests that are skipped or edited.**
  - Skips, each with its reason (`go test -v` lists 13): tests that set
    GODEBUG (8), tests that use the external network (2), and the three
    recorded renegotiation tests, because tlsx's renegotiation ClientHello
    differs.
  - tls_test.go: the FIPS 140 variant of a test is a skip (no FIPS mode);
    the Config.Clone test sets `Config.Ext`; the cipher-suite list tests
    leave out tlsx's extra suites (`isTLSXSuite`).
  - handshake_test.go: the BoGo shim hooks are removed (the shim is not
    carried).

## Pulling upstream changes

Do this for every Go release. Go's security releases announce crypto/tls
fixes on golang-announce. The weekly GitHub workflow does steps 1 and 2 by
itself: it opens an issue with the dry-run result.

1. `scripts/sync-upstream.sh go1.27.N` (or `latest`) writes the diff
   between the base and the new release (both rewritten as above) to
   `upstream-<base>-<new>.patch` and dry-runs it.
2. `scripts/sync-upstream.sh go1.27.N --apply` merges it file by file. It
   uses `git merge-file`, so conflicts show as `<<<<<<< tlsx` markers.
   `testdata/` is replaced by the new release's.
3. Regenerate `common_string.go`, which includes tlsx's groups and signature
   schemes. Build `golang.org/x/tools/cmd/stringer` and run
   `stringer -linecomment -type=SignatureScheme,CurveID,ClientAuthType -output=common_string.go .`
4. Set the `Base:` line above to the new release. If the release needs a
   newer Go, update the `go` line in `go.mod`.
5. Run these checks:
   - `gofmt -l .`
   - `go vet ./...`
   - `go test -race ./...` (the OpenSSL and GnuTLS interoperability tests run when those tools are installed)
   - `scripts/provenance.sh`
6. Delete the patch file and add a CHANGELOG entry.

A new Go major version is handled the same way, with more conflicts in the
handshake files. Check its crypto/tls for new internal imports:
`grep -h '"internal/\|"crypto/internal/' $(go env GOROOT)/src/crypto/tls/*.go`.
Public packages, such as `crypto/mldsa` in Go 1.27, are imported as they
are. Internal ones get a rewrite rule and a stand-in.

## History

- go1.26.2: first copy, made inside SigmaM2M.
- go1.26.6: KeyUpdate records no longer count as progress (DoS
  hardening); pre_shared_key is no longer sent in an Encrypted Client Hello
  outer hello.
- go1.27.1: ML-DSA signatures, ML-KEM-1024 key exchange, the new
  curve-preference logic and re-recorded testdata. The first standalone
  release is v0.1.0.

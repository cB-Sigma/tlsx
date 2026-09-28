# Tracking upstream

Base: go1.27.1 (src/crypto/tls, crypto/internal/fips140/tls12, tls13 and bigmod of the Go 1.27.1 release)

tlsx is a fork of Go's `crypto/tls`. Go's licence (BSD-3-Clause) is in
[LICENSE](LICENSE) with Go's [PATENTS](PATENTS) grant; what is Go's and
what is ours is in [NOTICE](NOTICE) and, file by file, in
[PROVENANCE.md](PROVENANCE.md).

## Go's history in this repository

tlsx's history starts with Go's own: every commit of the Go project that
touched a file tlsx carries is in this repository, with its original
author, committer, dates and message, rewritten only to tlsx's file
layout. `git blame` on a Go line names the Go commit and author that wrote
it; `git log --follow` goes back to 2009.

The upstream history is made by `scripts/filter-upstream.sh` with
[git filter-repo](https://github.com/newren/git-filter-repo) (2.47.0) from
a clone of <https://go.googlesource.com/go>:

```
scripts/filter-upstream.sh GO_REPO WORK_DIR go1.27.1
```

which runs, in a bare repository that borrows the clone's objects and has
only `refs/tags/upstream/go1.27.1`:

```
git filter-repo --force --preserve-commit-hashes --prune-empty always \
  --replace-refs delete-no-add \
  --path LICENSE --path PATENTS \
  --path src/crypto/tls/ --path src/pkg/crypto/tls/ \
  --path src/crypto/internal/fips140/tls12/tls12.go --path src/crypto/internal/fips/tls12/tls12.go \
  --path src/crypto/internal/fips140/tls13/tls13.go --path src/crypto/internal/fips/tls13/tls13.go \
  --path src/crypto/internal/{fips140/,fips/,}bigmod/{nat.go,nat_noasm.go,nat_test.go,testdata/} \
  --path src/crypto/rsa/nat.go --path src/crypto/rsa/nat_test.go \
  --path-rename src/crypto/rsa/nat.go:internal/bigmod/nat.go \
  --path-rename src/crypto/rsa/nat_test.go:internal/bigmod/nat_test.go \
  --path-rename src/crypto/internal/fips140/bigmod/:internal/bigmod/ \
  --path-rename src/crypto/internal/fips/bigmod/:internal/bigmod/ \
  --path-rename src/crypto/internal/bigmod/:internal/bigmod/ \
  --path-rename src/crypto/internal/fips140/tls12/:internal/tls12/ \
  --path-rename src/crypto/internal/fips/tls12/:internal/tls12/ \
  --path-rename src/crypto/internal/fips140/tls13/:internal/tls13/ \
  --path-rename src/crypto/internal/fips/tls13/:internal/tls13/ \
  --path-rename src/crypto/tls/: --path-rename src/pkg/crypto/tls/: \
  --filename-callback '<keep LICENSE, PATENTS, testdata/, internal/{bigmod,tls12,tls13}/
                        and the top-level .go files of crypto/tls that tlsx carries>'
```

(the script spells out each `--path` and the callback). The older paths
are where these files lived before: `src/pkg/crypto/tls` until Go 1.4,
`crypto/internal/fips/...` for a week in November 2024 before it became
`fips140`, `crypto/internal/bigmod` from 2022 to 2024, and
`crypto/rsa/nat.go` before that. `tls12.go` and `tls13.go` started in 2024
as new files (the code moved out of crypto/tls without a file rename), so
their history starts there; blame shows the 2024 commit for their lines.

Only commits reachable from the release tag are kept (855 for go1.27.1);
commits that change none of these files are dropped. The tag's own commit
only bumps `VERSION`, so `upstream/go1.27.1` is the last commit before it
that touched these files (Go's `bf05097a65`); its tree is byte for byte
Go 1.27.1's files.

[docs/upstream-commit-map.txt](docs/upstream-commit-map.txt) maps each
Go commit ID to its rewritten ID here. Commit messages are unchanged, so
the commit IDs they quote are Go's.

The filter is deterministic: the same Go commit always becomes the same
commit here. Filtering go1.27.1 alone or with other tags gives the same
855 IDs, and the sync checks this every time (below). Changing the filter
(a path, a rename or the file rule) would change every ID, so it must not
change; an unwanted new upstream file is deleted in tlsx instead.

On top of `upstream/go1.27.1` come tlsx's commits:

1. `tlsx: go.mod and stand-ins for Go-internal packages`: our files only
   (`go.mod`, `upstream_shims.go`, `upstream_shims_test.go`,
   `internal/boring`, `internal/cryptotest`, `internal/testenv`,
   `gcm_tls.go`);
2. `mechanical: rename package and rewrite Go-internal imports (no
   functional change)`: the rewrite below, nothing else;
3. `tlsx: add the adapters Go's code needs for crypto/cipher, crypto/hmac
   and crypto/hkdf`: the few lines we wrote inside Go's files, added next
   to the Go lines they replace;
4. `mechanical: replace BoringCrypto and FIPS-module calls with public
   crypto packages`: removes those branches, the lines the adapters
   replace and the BoGo shim hooks, and swaps imports; nothing added. The
   package and its tests build from here on;
5. `tlsx: skip upstream tests that need FIPS mode, GODEBUG or the
   network`: after it, tlsx is a plain fork that passes Go's tests;
6. the features, the interoperability tests, the header lines, the legal
   files, the documentation and CI.

The two `mechanical:` commits author no code; they are listed in
[.git-blame-ignore-revs](.git-blame-ignore-revs), which GitHub's blame
view reads. Locally, run `git config blame.ignoreRevsFile
.git-blame-ignore-revs` once; `git blame` then shows, for a rewritten line
such as `package tlsx`, the Go commit that wrote it. Lines we wrote are
kept out of the ignored commits, because `git blame` would pass over them
too. Commits 2 and 3 do not build on their own: Go's files build only once
the rewrite, the adapters and the removals are all in, and folding our
adapter lines into an ignored commit would hide them from blame.

## The mechanical rewrite

`scripts/upstream-lib.sh` holds the rules (`rewrite`); the sync and the
provenance script use them.

- **Files.** Every `.go` file of `src/crypto/tls` except:
  - the FIPS 140 tests (`fips140_test.go`);
  - `link_test.go`, `defaults_boring.go`, `generate_cert.go` and `example_test.go`;
  - `certificates_generator_test.go`.

  `certificates_test.go`, which the generator writes, is carried as is.
  `testdata/` is carried as is. Three packages of `crypto/internal/fips140`
  are carried too:
  - `tls12` becomes `internal/tls12`, using `crypto/hmac` instead of the FIPS module;
  - `tls13` becomes `internal/tls13`, using `crypto/hkdf`;
  - `bigmod` becomes `internal/bigmod`, the pure Go `nat_noasm.go` code path.

  The filter already leaves out everything else.
- **Rewrites.**
  - package `tls` becomes `tlsx`;
  - `//go:linkname` lines are removed; in `internal/bigmod`, `//go:build` lines too;
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

## The BoGo shim: copied, not filtered

`bogo_shim_test.go`, `bogo_shim_unix_test.go`, `bogo_shim_notunix_test.go`
and `bogo_config.json` (BoringSSL's conformance suite shim, README "BoGo")
came in with v0.3.0 as copies of Go 1.27.1's files, in the commit `tlsx:
copy Go 1.27.1's BoGo shim and configuration, unchanged`, followed by a
`mechanical:` rename. They are not in the filtered history: adding them to
`scripts/filter-upstream.sh` would change the ID of every commit since
Go's first shim commit (2073b35e07, April 2023), and published history is
not rewritten. So `git blame` shows that copy commit for their lines, and
their Go authors are in Go's own history of `src/crypto/tls/bogo_*`.

- `scripts/upstream-lib.sh` lists them (`UPSTREAM_COPIED`); the filter
  still leaves them out, and `provenance.sh` compares them with Go's.
- `scripts/sync-upstream.sh` merges Go's changes to them between the two
  releases (three ways, on rewritten texts) and commits the result apart.
  A conflict is reported and left for a hand update.
- `handshake_test.go` has Go's `-bogo-mode` lines in TestMain again.
- tlsx's shim flags are in `x_bogo_test.go`, reached through hooks marked
  `// tlsx` in `bogo_shim_test.go`; `bogo_config.json` stays Go's, and
  tlsx's expected failures are in `bogo_config_tlsx.json`.

## Pulling upstream changes

Do this for every Go release. Go's security releases announce crypto/tls
fixes on golang-announce. The weekly GitHub workflow runs the sync on a
scratch branch and opens an issue with the result; nothing is pushed.

You need a clone of Go (`git clone --no-checkout https://go.googlesource.com/go
go-upstream`, next to this repository or named by `TLSX_GO_REPO`) and
git-filter-repo. On `main`, with a clean working tree:

1. `scripts/sync-upstream.sh go1.27.N` (or `latest`). It:
   1. fetches the Go clone;
   2. filters the base release (the `Base:` line above) and the new one,
      and stops unless the filtered base is exactly `upstream/<base>` here
      (determinism check); then fetches the new release as
      `upstream/go1.27.N`;
   3. runs `git merge upstream/go1.27.N`. A conflicted file is retried
      three ways on rewritten texts: tlsx's side, the old release and the
      new one, both rewritten. That settles conflicts that come only from
      the rewrite, and those between release branches (Go's backports are
      on both sides when moving to a new major version); a file tlsx never
      changed becomes the new release's. Files tlsx does not carry stay
      deleted;
   4. commits the mechanical rewrite of the files upstream changed on its
      own (`mechanical: rewrite Go-internal imports in Go go1.27.N's
      changes`), then a record commit with the new `Base:` line, the
      extended commit map, a regenerated PROVENANCE.md and the rewrite
      commit added to `.git-blame-ignore-revs`;
   5. runs gofmt, `go vet`, `go test -race` (the OpenSSL and GnuTLS
      interoperability tests run when those tools are installed) and
      `scripts/provenance.sh --check`, with `GOTOOLCHAIN` set to the new
      release.

   If conflicts are left, it stops with status 2 and lists them (look for
   `<<<<<<< tlsx`). Resolve them, `git add` the files, and run
   `scripts/sync-upstream.sh --continue`, which commits the merge and does
   steps 4 and 5.
2. If upstream changed the constants in `common.go`, regenerate
   `common_string.go`, which includes tlsx's groups and signature schemes:
   build `golang.org/x/tools/cmd/stringer` and run
   `stringer -linecomment -type=SignatureScheme,CurveID,ClientAuthType -output=common_string.go .`
3. If the release needs a newer Go, update the `go` line in `go.mod`.
4. Add a CHANGELOG entry.

Moving to a new Go major version works the same way, with more conflicts
in the handshake files. Check its crypto/tls for new internal imports:
`git grep -h '"internal/\|"crypto/internal/' upstream/go1.N.0 -- '*.go'`.
Public packages, such as `crypto/mldsa` in Go 1.27, are imported as they
are. Internal ones get a rewrite rule and a stand-in.

The sync was tried from go1.26.6 to go1.27.1 on throwaway branches: with
only the mechanical rewrite on go1.26.6, every conflict (9 files) was
settled automatically and the result equalled the direct rewrite of
go1.27.1; with tlsx's code of that time, 4 conflicts were settled and 12
files needed a hand resolution.

## History

- go1.26.2: first copy, made inside SigmaM2M.
- go1.26.6: KeyUpdate records no longer count as progress (DoS
  hardening); pre_shared_key is no longer sent in an Encrypted Client Hello
  outer hello.
- go1.27.1: ML-DSA signatures, ML-KEM-1024 key exchange, the new
  curve-preference logic and re-recorded testdata. The first standalone
  release is v0.1.0.
- v0.1.0 was first a one-commit snapshot; its history was rebuilt on Go's
  own history before it was published. The tree is the same.

#!/usr/bin/env bash
# Copyright 2026 Abhinav Gautam. Use of this source code is governed
# by the BSD-style licence in the LICENSE file.
#
# filter-upstream.sh: turn Go's history into tlsx's upstream history.
#
#   scripts/filter-upstream.sh GO_REPO WORK_DIR TAG...
#
# GO_REPO is a clone of https://go.googlesource.com/go (it is only read).
# WORK_DIR must not exist; it becomes a bare repository that borrows
# GO_REPO's objects (objects/info/alternates) and holds one ref per TAG,
# refs/tags/upstream/TAG, rewritten by git filter-repo to the files tlsx
# carries, in tlsx's layout. Every kept commit keeps its author, committer,
# dates and message (hashes quoted in messages are left as they are).
# WORK_DIR/filter-repo/commit-map maps Go's commit IDs to the rewritten ones.
#
# The filter is deterministic: the same Go commit always becomes the same
# rewritten commit, so filtering a newer tag reproduces the IDs already in
# tlsx and only adds the new commits. Changing FILTER below (a path, a
# rename or the file rule) changes the IDs and must never be done casually;
# drop an unwanted new upstream file in tlsx instead.
set -euo pipefail

gorepo="$(cd "${1:?usage: $0 GO_REPO WORK_DIR TAG...}" && pwd)"
work="${2:?usage: $0 GO_REPO WORK_DIR TAG...}"
shift 2
[ $# -gt 0 ] || { echo "usage: $0 GO_REPO WORK_DIR TAG..." >&2; exit 1; }
[ ! -e "$work" ] || { echo "$work exists; give a new directory" >&2; exit 1; }

objects="$(git -C "$gorepo" rev-parse --path-format=absolute --git-path objects)"
git init -q --bare "$work"
echo "$objects" > "$work/objects/info/alternates"
for tag in "$@"; do
	git -C "$work" update-ref "refs/tags/upstream/$tag" "$(git -C "$gorepo" rev-parse "$tag^{commit}")"
done

# The paths, current and historical, of the files tlsx carries:
#   src/crypto/tls (src/pkg/crypto/tls until Go 1.4)          -> .
#   src/crypto/internal/fips140/tls12/tls12.go (fips/ in 2024-11)
#                                                             -> internal/tls12
#   src/crypto/internal/fips140/tls13/tls13.go (fips/ in 2024-11)
#                                                             -> internal/tls13
#   src/crypto/internal/fips140/bigmod nat.go, nat_noasm.go, nat_test.go,
#   testdata (fips/bigmod in 2024-11, crypto/internal/bigmod 2022-2024,
#   crypto/rsa/nat.go and nat_test.go 2021-2022)              -> internal/bigmod
#   LICENSE, PATENTS                                          -> .
# The file rule (the callback) then keeps, of crypto/tls, the top-level .go
# files and testdata/, less the files tlsx does not carry (upstream-lib.sh).
# The BoGo shim stays out of the filter although tlsx now carries it: it
# came in as a copy (upstream-lib.sh, UPSTREAM_COPIED), because filtering
# it in would change every commit ID since 2023.
cd "$work"
git filter-repo --force \
	--preserve-commit-hashes \
	--prune-empty always \
	--replace-refs delete-no-add \
	--path LICENSE \
	--path PATENTS \
	--path src/crypto/tls/ \
	--path src/pkg/crypto/tls/ \
	--path src/crypto/internal/fips140/tls12/tls12.go \
	--path src/crypto/internal/fips/tls12/tls12.go \
	--path src/crypto/internal/fips140/tls13/tls13.go \
	--path src/crypto/internal/fips/tls13/tls13.go \
	--path src/crypto/internal/fips140/bigmod/nat.go \
	--path src/crypto/internal/fips140/bigmod/nat_noasm.go \
	--path src/crypto/internal/fips140/bigmod/nat_test.go \
	--path src/crypto/internal/fips140/bigmod/testdata/ \
	--path src/crypto/internal/fips/bigmod/nat.go \
	--path src/crypto/internal/fips/bigmod/nat_noasm.go \
	--path src/crypto/internal/fips/bigmod/nat_test.go \
	--path src/crypto/internal/fips/bigmod/testdata/ \
	--path src/crypto/internal/bigmod/nat.go \
	--path src/crypto/internal/bigmod/nat_noasm.go \
	--path src/crypto/internal/bigmod/nat_test.go \
	--path src/crypto/internal/bigmod/testdata/ \
	--path src/crypto/rsa/nat.go \
	--path src/crypto/rsa/nat_test.go \
	--path-rename src/crypto/rsa/nat.go:internal/bigmod/nat.go \
	--path-rename src/crypto/rsa/nat_test.go:internal/bigmod/nat_test.go \
	--path-rename src/crypto/internal/fips140/bigmod/:internal/bigmod/ \
	--path-rename src/crypto/internal/fips/bigmod/:internal/bigmod/ \
	--path-rename src/crypto/internal/bigmod/:internal/bigmod/ \
	--path-rename src/crypto/internal/fips140/tls12/:internal/tls12/ \
	--path-rename src/crypto/internal/fips/tls12/:internal/tls12/ \
	--path-rename src/crypto/internal/fips140/tls13/:internal/tls13/ \
	--path-rename src/crypto/internal/fips/tls13/:internal/tls13/ \
	--path-rename src/crypto/tls/: \
	--path-rename src/pkg/crypto/tls/: \
	--filename-callback '
n = filename
if n is None:
    return None
if n in (b"LICENSE", b"PATENTS"):
    return n
for d in (b"testdata/", b"internal/bigmod/", b"internal/tls12/", b"internal/tls13/"):
    if n.startswith(d):
        return n
if b"/" in n or not n.endswith(b".go"):
    return None
if n.startswith(b"bogo_shim_") or n in (b"fips140_test.go", b"link_test.go",
        b"defaults_boring.go", b"generate_cert.go", b"example_test.go",
        b"certificates_generator_test.go"):
    return None
return n
'

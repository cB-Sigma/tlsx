# Copyright 2026 Abhinav Gautam. Use of this source code is governed
# by the BSD-style licence in the LICENSE file.
#
# upstream-lib.sh: shared by sync-upstream.sh and provenance.sh. It holds
# the mechanical rewrite that turns Go's files (in tlsx's layout, as
# scripts/filter-upstream.sh lays them out) into tlsx's, and extracts the
# files tlsx carries from a Go release (GOROOT), rewritten, so the result
# can be compared with this repository.

MODULE="github.com/cB-Abhinav-Gautam/tlsx"

# Upstream crypto/tls files tlsx does not carry (and why):
#   bogo_shim_*          BoringSSL's BoGo test runner shim (see README)
#   fips140_test.go      FIPS 140-3 mode tests (tlsx has no FIPS mode)
#   link_test.go         linker checks of the standard library build
#   defaults_boring.go   BoringCrypto defaults
#   generate_cert.go     a command (package main)
#   example_test.go      examples of the crypto/tls API
#   certificates_generator_test.go  regenerates certificates_test.go with a
#                        FIPS module version check (internal API)
upstream_excluded() {
	case "$1" in
	bogo_shim_*|fips140_test.go|link_test.go|defaults_boring.go|generate_cert.go|example_test.go|certificates_generator_test.go) return 0 ;;
	esac
	return 1
}

# goroot VERSION prints the GOROOT of Go VERSION (fetched through GOTOOLCHAIN
# when it is not installed).
goroot() {
	local d
	d="$(mktemp -d)"
	(cd "$d" && GOTOOLCHAIN="$1" go env GOROOT)
	rmdir "$d"
}

# rewrite ROOT FILE...: apply the mechanical rewrite, in place, to the named
# files (paths relative to ROOT, in tlsx's layout; files that are not .go
# are left alone). The rewrite is idempotent: a file already rewritten does
# not change. The sync runs it on the files an upstream merge changed.
rewrite() {
	local root="$1" f
	shift
	local gofiles=() bigmod=()
	for f in "$@"; do
		case "$f" in *.go) ;; *) continue ;; esac
		[ -e "$root/$f" ] || continue
		gofiles+=("$root/$f")
		case "$f" in internal/bigmod/*) bigmod+=("$root/$f") ;; esac
	done
	[ ${#gofiles[@]} -gt 0 ] || return 0
	# sed writes a new file that replaces the old one (no in-place flag:
	# BSD and GNU sed differ there).
	for f in "${gofiles[@]}"; do
		sed \
			-e 's/^package tls$/package tlsx/' -e 's/^package tls_test$/package tlsx_test/' \
			-e '/^\/\/go:linkname/d' \
			-e '/^	"internal\/godebug"$/d' -e '/^	"crypto\/tls\/internal\/fips140tls"$/d' -e '/^	"internal\/byteorder"$/d' \
			-e '/^	_ "crypto\/internal\/fips140\/check"$/d' \
			-e '/^	internalrand "crypto\/internal\/rand"$/d' \
			-e "s#\"crypto/internal/fips140/tls13\"#\"$MODULE/internal/tls13\"#" \
			-e "s#\"crypto/internal/fips140/tls12\"#\"$MODULE/internal/tls12\"#" \
			-e "s#^	\"crypto/internal/boring\"\$#	\"$MODULE/internal/boring\"#" \
			-e "s#^	\"crypto/internal/cryptotest\"\$#	\"$MODULE/internal/cryptotest\"#" \
			-e "s#^	\"internal/testenv\"\$#	\"$MODULE/internal/testenv\"#" \
			-e 's#"internal/cpu"#"golang.org/x/sys/cpu"#' \
			"$f" > "$f.rewrite" && mv -- "$f.rewrite" "$f"
	done
	# bigmod only: tlsx carries the pure Go code path (nat_noasm.go without
	# its build constraint), and the internal byteorder becomes
	# encoding/binary (the tlsx package keeps upstream's byteorder calls,
	# see upstream_shims.go).
	for f in "${bigmod[@]+"${bigmod[@]}"}"; do
		sed \
			-e '/^\/\/go:build/d' \
			-e 's#^	"crypto/internal/fips140deps/byteorder"$#	"encoding/binary"#' \
			-e 's#byteorder\.BEUint64(#binary.BigEndian.Uint64(#g' \
			-e 's#byteorder\.BEUint32(#binary.BigEndian.Uint32(#g' \
			"$f" > "$f.rewrite" && mv -- "$f.rewrite" "$f"
	done
	gofmt -w "${gofiles[@]}"
}

# upstream_files ROOT: list, relative to ROOT, the files of a tree in tlsx's
# layout that come from Go (what filter-upstream.sh keeps).
upstream_files() {
	(cd "$1" && {
		ls *.go | while IFS= read -r f; do upstream_excluded "$f" || echo "$f"; done
		find testdata internal/tls12 internal/tls13 internal/bigmod -type f 2>/dev/null
	} | sort)
}

# extract GOROOT DST: copy the files tlsx carries from a Go release into
# tlsx's layout, and rewrite them.
extract() {
	local src="$1/src" dst="$2" f
	mkdir -p "$dst/internal/tls13" "$dst/internal/tls12" "$dst/internal/bigmod/testdata" "$dst/testdata"
	for f in "$src"/crypto/tls/*.go; do
		upstream_excluded "$(basename "$f")" && continue
		cp "$f" "$dst/"
	done
	cp "$src"/crypto/tls/testdata/* "$dst/testdata/"
	cp "$src/crypto/internal/fips140/tls13/tls13.go" "$dst/internal/tls13/"
	cp "$src/crypto/internal/fips140/tls12/tls12.go" "$dst/internal/tls12/"
	cp "$src/crypto/internal/fips140/bigmod/nat.go" "$src/crypto/internal/fips140/bigmod/nat_noasm.go" \
		"$src/crypto/internal/fips140/bigmod/nat_test.go" "$dst/internal/bigmod/"
	cp "$src"/crypto/internal/fips140/bigmod/testdata/* "$dst/internal/bigmod/testdata/"
	chmod -R u+w "$dst"
	local files=()
	while IFS= read -r f; do files+=("$f"); done < <(cd "$dst" && find . -name '*.go' | sed 's#^\./##' | sort)
	rewrite "$dst" "${files[@]}"
}

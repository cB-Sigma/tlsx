# Copyright 2026 Abhinav Gautam. Use of this source code is governed
# by the BSD-style licence in the LICENSE file.
#
# upstream-lib.sh: shared by sync-upstream.sh and provenance.sh. It extracts
# the files tlsx carries from a Go release (GOROOT) into tlsx's layout and
# applies the same mechanical rewrites tlsx applied, so the result can be
# compared with, or merged into, this repository.

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

# extract GOROOT DST: copy and rewrite.
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
	find "$dst" -name '*.go' -print0 | xargs -0 sed -i.orig \
		-e 's/^package tls$/package tlsx/' -e 's/^package tls_test$/package tlsx_test/' \
		-e '/^\/\/go:linkname/d' -e '/^\/\/go:build/d' \
		-e '/^	"internal\/godebug"$/d' -e '/^	"crypto\/tls\/internal\/fips140tls"$/d' -e '/^	"internal\/byteorder"$/d' \
		-e '/^	_ "crypto\/internal\/fips140\/check"$/d' \
		-e '/^	internalrand "crypto\/internal\/rand"$/d' \
		-e "s#\"crypto/internal/fips140/tls13\"#\"$MODULE/internal/tls13\"#" \
		-e "s#\"crypto/internal/fips140/tls12\"#\"$MODULE/internal/tls12\"#" \
		-e "s#^	\"crypto/internal/boring\"\$#	\"$MODULE/internal/boring\"#" \
		-e "s#^	\"crypto/internal/cryptotest\"\$#	\"$MODULE/internal/cryptotest\"#" \
		-e "s#^	\"internal/testenv\"\$#	\"$MODULE/internal/testenv\"#" \
		-e 's#"internal/cpu"#"golang.org/x/sys/cpu"#'
	# bigmod only: its internal byteorder becomes encoding/binary (the tlsx
	# package keeps upstream's byteorder calls, see upstream_shims.go).
	sed -i.orig \
		-e 's#^	"crypto/internal/fips140deps/byteorder"$#	"encoding/binary"#' \
		-e 's#byteorder\.BEUint64(#binary.BigEndian.Uint64(#g' \
		-e 's#byteorder\.BEUint32(#binary.BigEndian.Uint32(#g' \
		"$dst/internal/bigmod/nat.go"
	find "$dst" -name '*.orig' -print0 | xargs -0 rm -f
	gofmt -w "$dst"
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import "encoding/binary"

// This file stands in for the standard library internals that the
// upstream crypto/tls imports and a package outside GOROOT cannot: FIPS
// 140 mode (never required here), GODEBUG settings (x_godebug.go) and
// internal/byteorder. The upstream call sites stay unchanged
// so security fixes merge with small diffs (UPSTREAM.md).

type fipsShim struct{}

// Required reports whether FIPS 140-3 TLS rules apply: never in tlsx.
func (fipsShim) Required() bool { return false }

var fips140tls fipsShim

// godebug stands in for internal/godebug: the settings are real (the
// GODEBUG environment variable, then the build's defaults), see
// x_godebug.go.
var godebug godebugShim

type byteorderShim struct{}

func (byteorderShim) LEUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

var byteorder byteorderShim

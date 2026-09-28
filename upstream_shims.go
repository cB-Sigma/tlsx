// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import "encoding/binary"

// This file stands in for the standard library internals that the
// upstream crypto/tls imports and a package outside GOROOT cannot: FIPS
// 140 mode (never required here), GODEBUG settings (always at their
// default) and internal/byteorder. The upstream call sites stay unchanged
// so security fixes merge with small diffs (UPSTREAM.md).

type fipsShim struct{}

// Required reports whether FIPS 140-3 TLS rules apply: never in tlsx.
func (fipsShim) Required() bool { return false }

var fips140tls fipsShim

type godebugShim struct{}

// godebugSetting is a GODEBUG setting fixed at its default.
type godebugSetting struct{ name string }

func (godebugShim) New(name string) *godebugSetting { return &godebugSetting{name: name} }

// Value is "" (the default behaviour of every setting).
func (*godebugSetting) Value() string { return "" }

// IncNonDefault would count a non-default use; defaults never are.
func (*godebugSetting) IncNonDefault() {}

// Name is the setting name.
func (s *godebugSetting) Name() string { return s.name }

var godebug godebugShim

type byteorderShim struct{}

func (byteorderShim) LEUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

var byteorder byteorderShim

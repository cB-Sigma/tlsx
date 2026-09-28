// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package cryptotest stands in for the standard library's
// crypto/internal/cryptotest in the upstream crypto/tls tests that tlsx
// carries. tlsx has no FIPS 140 module of its own, so the module version
// checks always pass: the algorithms come from the public crypto packages
// of the Go toolchain that builds tlsx.
package cryptotest

import "testing"

// MustMinimumFIPS140ModuleVersion does nothing in tlsx.
func MustMinimumFIPS140ModuleVersion(t testing.TB, version string) { t.Helper() }

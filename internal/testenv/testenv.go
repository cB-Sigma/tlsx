// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package testenv stands in for the standard library's internal/testenv in
// the upstream crypto/tls tests that tlsx carries. It provides only what
// those tests call, with tlsx's behaviour: GODEBUG settings are fixed at
// their defaults and the tests never use the external network.
package testenv

import "testing"

// SetGODEBUG skips the test: tlsx ignores GODEBUG.
func SetGODEBUG(t testing.TB, godebug string) {
	t.Helper()
	t.Skipf("tlsx ignores GODEBUG (%s)", godebug)
}

// MustHaveExternalNetwork skips the test.
func MustHaveExternalNetwork(t testing.TB) {
	t.Helper()
	t.Skip("tlsx: tests do not use the external network")
}

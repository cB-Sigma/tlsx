// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package testenv stands in for the standard library's internal/testenv in
// the upstream crypto/tls tests that tlsx carries. It provides only what
// those tests call, with tlsx's behaviour: the tests never use the
// external network (the BoGo
// suite fetches BoringSSL only when asked, see bogo_shim_test.go).
package testenv

import (
	"os"
	"os/exec"
	"testing"
)

// GODEBUGChanged, if set, is called when SetGODEBUG changes GODEBUG and
// when the test restores it: tlsx reads its settings once (x_godebug.go)
// and its tests set this to make it read them again.
var GODEBUGChanged func()

// SetGODEBUG appends a setting to GODEBUG for the test, as Go's testenv
// does (the test must not be parallel).
func SetGODEBUG(t testing.TB, godebug string) {
	t.Helper()
	if GODEBUGChanged != nil {
		t.Cleanup(GODEBUGChanged) // runs after GODEBUG is restored
	}
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+","+godebug)
	if GODEBUGChanged != nil {
		GODEBUGChanged()
	}
}

// MustHaveExternalNetwork skips the test.
func MustHaveExternalNetwork(t testing.TB) {
	t.Helper()
	t.Skip("tlsx: tests do not use the external network")
}

// Builder is the name of the Go project's builder running the test; tlsx
// never runs on those builders, so it is always "".
func Builder() string { return "" }

// MustHaveExecPath skips the test when the program is not on PATH.
func MustHaveExecPath(t testing.TB, program string) {
	t.Helper()
	if _, err := exec.LookPath(program); err != nil {
		t.Skipf("tlsx: %s is not on PATH", program)
	}
}

// GoToolPath is the go command on PATH (with GOTOOLCHAIN honoured by it).
func GoToolPath(t testing.TB) string {
	t.Helper()
	p, err := exec.LookPath("go")
	if err != nil {
		t.Skip("tlsx: the go command is not on PATH")
	}
	return p
}

// Executable is the path of the running test binary.
func Executable(t testing.TB) string {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatalf("tlsx: path of the test binary: %v", err)
	}
	return p
}

// Command is exec.Command, stopped when the test's context ends.
func Command(t testing.TB, name string, args ...string) *exec.Cmd {
	t.Helper()
	return exec.CommandContext(t.Context(), name, args...)
}

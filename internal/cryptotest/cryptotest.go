// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package cryptotest stands in for the standard library's
// crypto/internal/cryptotest in the upstream crypto/tls tests that tlsx
// carries. tlsx has no FIPS 140 module of its own, so the module version
// checks always pass: the algorithms come from the public crypto packages
// of the Go toolchain that builds tlsx.
package cryptotest

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// MustMinimumFIPS140ModuleVersion does nothing in tlsx.
func MustMinimumFIPS140ModuleVersion(t testing.TB, version string) { t.Helper() }

// FetchModule downloads module@version with "go mod download" (through
// GOPROXY, into the module cache) and returns its directory. tlsx's tests
// do not use the network unless asked: the test is skipped unless the
// environment has TLSX_BOGO=1 (scripts/bogo.sh sets it).
func FetchModule(t *testing.T, module, version string) string {
	t.Helper()
	if os.Getenv("TLSX_BOGO") != "1" {
		t.Skipf("tlsx: set TLSX_BOGO=1 to fetch %s (scripts/bogo.sh)", module)
	}
	t.Logf("go mod download %s@%s", module, version)
	var stderr strings.Builder
	cmd := exec.CommandContext(t.Context(), "go", "mod", "download", "-json", module+"@"+version)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go mod download %s@%s: %v\n%s%s", module, version, err, out, stderr.String())
	}
	var info struct{ Dir, Error string }
	if err := json.Unmarshal(out, &info); err != nil || info.Dir == "" {
		t.Fatalf("go mod download %s@%s: no directory in %q (%v %s)", module, version, out, err, info.Error)
	}
	return info.Dir
}

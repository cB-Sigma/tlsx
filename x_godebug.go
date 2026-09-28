// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
)

// GODEBUG settings, as crypto/tls reads them. The upstream code calls
// godebug.New(name).Value() and IncNonDefault() as with internal/godebug,
// which a package outside the standard library cannot import. The value of
// a setting is, in this order:
//
//  1. the GODEBUG environment variable, if it names the setting (the last
//     occurrence wins, as in Go);
//  2. the build's default: the DefaultGODEBUG build setting that the go
//     command records from the main module's go version, its godebug
//     lines and //go:debug directives (runtime/debug.ReadBuildInfo);
//  3. otherwise "", Go's current default.
//
// Both are read once, at the first use of any setting. Unlike Go's own
// settings, a later change of GODEBUG with os.Setenv is not seen, and the
// runtime/metrics counters /godebug/non-default-behavior/... are not fed;
// GODEBUGNonDefault reports the same counts instead.

type godebugShim struct{}

// godebugSetting is one setting (upstream: *godebug.Setting).
type godebugSetting struct {
	name       string
	nonDefault atomic.Uint64
}

var godebugSettings sync.Map // name -> *godebugSetting

func (godebugShim) New(name string) *godebugSetting {
	s, _ := godebugSettings.LoadOrStore(name, &godebugSetting{name: name})
	return s.(*godebugSetting)
}

// Name is the setting's name.
func (s *godebugSetting) Name() string { return s.name }

// Value is the setting's value ("" for Go's default).
func (s *godebugSetting) Value() string { return godebugValues()[s.name] }

// IncNonDefault counts a use of the non-default behaviour.
func (s *godebugSetting) IncNonDefault() { s.nonDefault.Add(1) }

// readBuildInfo is replaced in tests.
var readBuildInfo = debug.ReadBuildInfo

var (
	godebugMu  sync.Mutex
	godebugMap atomic.Pointer[map[string]string]
)

// godebugValues are the effective settings, read at the first call.
func godebugValues() map[string]string {
	if m := godebugMap.Load(); m != nil {
		return *m
	}
	godebugMu.Lock()
	defer godebugMu.Unlock()
	if m := godebugMap.Load(); m != nil {
		return *m
	}
	m := map[string]string{}
	if bi, ok := readBuildInfo(); ok {
		for _, kv := range bi.Settings {
			if kv.Key == "DefaultGODEBUG" {
				parseGODEBUG(m, kv.Value)
			}
		}
	}
	parseGODEBUG(m, os.Getenv("GODEBUG"))
	godebugMap.Store(&m)
	return m
}

// parseGODEBUG adds the key=value pairs of a comma-separated list to m;
// a later pair overrides an earlier one and what m had.
func parseGODEBUG(m map[string]string, list string) {
	for kv := range strings.SplitSeq(list, ",") {
		if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && k != "" {
			m[k] = v
		}
	}
}

// godebugReset makes the next use read the settings again (tests only).
func godebugReset() { godebugMap.Store(nil) }

// GODEBUGValue returns the value tlsx uses for the GODEBUG setting name
// ("" means Go's default behaviour). The settings crypto/tls reads, and so
// tlsx, are tlssha1, tlsmlkem, tlssecpmlkem, tlsmaxrsasize and fips140ems
// (the last only matters in FIPS 140-3 mode, which tlsx does not have).
func GODEBUGValue(name string) string { return godebugValues()[name] }

// GODEBUGNonDefault returns how many times tlsx used the non-default
// behaviour of the GODEBUG setting name in this process: what Go counts
// in runtime/metrics as /godebug/non-default-behavior/<name>:events. For
// tlssha1 it counts SHA-1 signatures in TLS 1.2 handshakes, whether
// GODEBUG or Config.Ext.AllowSHA1Signatures allowed them.
func GODEBUGNonDefault(name string) uint64 {
	if s, ok := godebugSettings.Load(name); ok {
		return s.(*godebugSetting).nonDefault.Load()
	}
	return 0
}

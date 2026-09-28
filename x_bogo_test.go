// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"testing"
)

// tlsx's part of the BoGo shim (bogo_shim_test.go, Go's, with hooks marked
// "// tlsx"). It maps BoGo's shim flags for features crypto/tls lacks onto
// Config.Ext, and adds bogo_config_tlsx.json: the BoGo tests tlsx fails on
// purpose, each with its reason. The flags follow BoringSSL's shim
// (ssl/test/test_config.cc); unknown flags still make the shim exit 89, so
// the runner skips those tests as unimplemented.

var (
	xBogoPSK         = flag.String("psk", "", "")
	xBogoPSKIdentity = flag.String("psk-identity", "", "")

	xBogoRenegotiateFreely = flag.Bool("renegotiate-freely", false, "")
	xBogoRenegotiateOnce   = flag.Bool("renegotiate-once", false, "")
	xBogoExpectRenegs      = flag.Int("expect-total-renegotiations", -1, "")
	xBogoExpectSecureReneg = flag.Bool("expect-secure-renegotiation", false, "")
	xBogoExpectNoSecReneg  = flag.Bool("expect-no-secure-renegotiation", false, "")

	xBogoKeyUpdate = flag.Bool("key-update", false, "")

	xBogoNoTicket = flag.Bool("no-ticket", false, "")

	xBogoExportLen     = flag.Int("export-keying-material", 0, "")
	xBogoExportLabel   = flag.String("export-label", "", "")
	xBogoExportContext = flag.String("export-context", "", "")
	xBogoExportUseCtx  = flag.Bool("use-export-context", false, "")

	xBogoSummaryFile = flag.String("bogo-tlsx-summary", "", "File path to write the BoGo results as JSON, with tlsx's expected failures marked")
)

// xBogoConfig applies the tlsx flags to the shim's configuration.
func xBogoConfig(cfg *Config) {
	if *xBogoPSK != "" {
		identity, key := []byte(*xBogoPSKIdentity), []byte(*xBogoPSK)
		cfg.Ext.PSK = &PSKConfig{
			// BoringSSL's shim sends its identity as the server's hint, and
			// as a client expects that hint (or none if it has no identity).
			Hint:       identity,
			Resumption: true,
			ClientKey: func(hint []byte) ([]byte, []byte, error) {
				if !bytes.Equal(hint, identity) {
					return nil, nil, fmt.Errorf("server PSK hint %q, want %q", hint, identity)
				}
				return identity, key, nil
			},
			Lookup: func(_ context.Context, id []byte) ([]byte, error) {
				if !bytes.Equal(id, identity) {
					return nil, nil
				}
				return key, nil
			},
		}
		for id := range pskSuiteNames {
			cfg.CipherSuites = append(cfg.CipherSuites, id)
		}
		slices.Sort(cfg.CipherSuites[len(cfg.CipherSuites)-len(pskSuiteNames):])
	}
	switch {
	case *xBogoRenegotiateFreely:
		cfg.Renegotiation = RenegotiateFreelyAsClient
	case *xBogoRenegotiateOnce:
		cfg.Renegotiation = RenegotiateOnceAsClient
	}
	if *xBogoNoTicket {
		// BoringSSL then resumes TLS 1.2 sessions by session ID.
		cfg.SessionTicketsDisabled = true
		cfg.Ext.ServerSessionCache = &xBogoSessionCache{m: map[string]*SessionState{}}
		cfg.Ext.ClientSessionIDs = true
	}
}

// xBogoSessionCache is a ServerSessionCache for one shim process.
type xBogoSessionCache struct{ m map[string]*SessionState }

func (c *xBogoSessionCache) Get(id string) (*SessionState, bool) { s, ok := c.m[id]; return s, ok }
func (c *xBogoSessionCache) Put(id string, s *SessionState)      { c.m[id] = s }

// xBogoAfterHandshake runs the steps BoringSSL's shim takes right after
// the handshake: -export-keying-material writes the exported value. A
// failure ends the shim as the echo loop's errors do.
func xBogoAfterHandshake(c *Conn) {
	if err := xBogoExport(c); err != nil {
		orderlyShutdown(c)
		log.Fatalf("conn error: %s", err)
	}
}

func xBogoExport(c *Conn) error {
	if *xBogoExportLen <= 0 {
		return nil
	}
	if err := c.Handshake(); err != nil {
		return err
	}
	var ctx []byte
	if *xBogoExportUseCtx {
		ctx = []byte(*xBogoExportContext)
	}
	cs := c.ConnectionState()
	ekm, err := cs.ExportKeyingMaterial(*xBogoExportLabel, ctx, *xBogoExportLen)
	if err != nil {
		return err
	}
	_, err = c.Write(ekm)
	return err
}

// xBogoAfterRead runs after each successful read of the echo loop.
func xBogoAfterRead(c *Conn) {
	if *xBogoKeyUpdate {
		if err := c.SendKeyUpdate(false); err != nil {
			log.Fatalf("SendKeyUpdate: %v", err)
		}
	}
}

// xBogoCheckState checks the connection state the tlsx flags expect.
func xBogoCheckState(cs ConnectionState) {
	if n := cs.Ext.Handshakes - 1; *xBogoExpectRenegs >= 0 && n != *xBogoExpectRenegs {
		log.Fatalf("expected %d renegotiations, got %d", *xBogoExpectRenegs, n)
	}
	// BoringSSL reports TLS 1.3 connections as secure: they cannot
	// renegotiate at all.
	secure := cs.Ext.SecureRenegotiation || cs.Version == VersionTLS13
	if *xBogoExpectSecureReneg && !secure {
		log.Fatal("no secure renegotiation when expected")
	}
	if *xBogoExpectNoSecReneg && secure {
		log.Fatal("secure renegotiation unexpectedly negotiated")
	}
}

// xBogoTLSXConfig is bogo_config_tlsx.json.
type xBogoTLSXConfig struct {
	// ExpectedFailures are the BoGo tests tlsx fails on purpose: test name
	// patterns ("*" matches any run of characters) with the reason. They
	// run; one that passes is reported, so the list stays true.
	ExpectedFailures map[string]string
}

var xBogoExpected xBogoTLSXConfig

func xBogoLoadExpected(t *testing.T) {
	b, err := os.ReadFile("bogo_config_tlsx.json")
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&xBogoExpected); err != nil {
		t.Fatalf("bogo_config_tlsx.json: %v", err)
	}
}

// xBogoExpectedFailure is the reason test name is listed as a tlsx
// expected failure ("" if it is not).
func xBogoExpectedFailure(name string) string {
	for pat, reason := range xBogoExpected.ExpectedFailures {
		// path.Match's "*" does not cross "/", which BoGo names do not use.
		if ok, _ := path.Match(pat, name); ok {
			return reason
		}
	}
	return ""
}

// xBogoCheckExpected handles a test tlsx expects to fail. It reports
// whether the test was handled (and Go's checks are to be skipped).
func xBogoCheckExpected(t *testing.T, name, actual string) bool {
	reason := xBogoExpectedFailure(name)
	if reason == "" {
		return false
	}
	switch actual {
	case "FAIL":
		t.Logf("expected failure (tlsx): %s", reason)
	case "PASS":
		t.Errorf("listed in bogo_config_tlsx.json (%s) but passed: remove it", reason)
	default:
		t.Skipf("listed in bogo_config_tlsx.json (%s); %s", reason, actual)
	}
	return true
}

// xBogoSummary logs the counts and writes -bogo-tlsx-summary.
func xBogoSummary(t *testing.T, results *bogoResults) {
	type entry struct {
		Name, Actual, Error, TLSXExpected string `json:",omitempty"`
	}
	counts := map[string]int{}
	var out []entry
	for name, r := range results.Tests {
		reason := xBogoExpectedFailure(name)
		k := r.Actual
		if reason != "" && r.Actual == "FAIL" {
			k = "FAIL (tlsx expected)"
		}
		counts[k]++
		out = append(out, entry{Name: name, Actual: r.Actual, Error: r.Error, TLSXExpected: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	var keys []string
	for k := range counts {
		keys = append(keys, fmt.Sprintf("%s %d", k, counts[k]))
	}
	sort.Strings(keys)
	t.Logf("BoGo %s: %d tests: %s", boringsslModVer, len(results.Tests), strings.Join(keys, ", "))
	if *xBogoSummaryFile == "" {
		return
	}
	b, err := json.MarshalIndent(struct {
		Revision string
		Counts   map[string]int
		Tests    []entry
	}{boringsslModVer, counts, out}, "", "\t")
	if err == nil {
		err = os.WriteFile(*xBogoSummaryFile, b, 0o644)
	}
	if err != nil {
		t.Error(errors.Join(errors.New("writing -bogo-tlsx-summary"), err))
	}
}

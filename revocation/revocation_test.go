// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// fileSources writes the CRLs of the intermediate and the root to dir and
// returns sources for them.
func fileSources(t *testing.T, p *pki, interCRL, rootCRL []byte, pol Policy) []Source {
	dir := t.TempDir()
	return []Source{
		{Issuer: p.inter.cert, File: writeFile(t, dir, "inter.crl", interCRL), Policy: pol},
		{Issuer: p.root.cert, File: writeFile(t, dir, "root.crl", rootCRL), Policy: pol},
	}
}

func TestRevokedLeaf(t *testing.T) {
	p := newPKI(t)
	c := mustNew(t, Config{DisableRefresh: true, Sources: fileSources(t, p,
		p.inter.makeCRL(t, crlOpts{number: 1}, p.bad), p.root.makeCRL(t, crlOpts{number: 1}), FailClosed)})

	err := c.CheckChain(p.chain(p.bad))
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("revoked leaf: got %v, want ErrRevoked", err)
	}
	var re *RevokedError
	if !errors.As(err, &re) || re.Serial.Cmp(p.bad.SerialNumber) != 0 || re.Reason != 1 ||
		re.Source != p.inter.cert.Subject.String() {
		t.Fatalf("RevokedError = %+v", re)
	}
	if !strings.Contains(err.Error(), "keyCompromise") {
		t.Errorf("error %q does not name the reason", err)
	}
	if err := c.CheckChain(p.chain(p.good)); err != nil {
		t.Fatalf("unrevoked leaf refused: %v", err)
	}
}

func TestRevokedIntermediate(t *testing.T) {
	p := newPKI(t)
	c := mustNew(t, Config{DisableRefresh: true, Sources: fileSources(t, p,
		p.inter.makeCRL(t, crlOpts{number: 1}), p.root.makeCRL(t, crlOpts{number: 1}, p.inter.cert), FailClosed)})
	var re *RevokedError
	if err := c.CheckChain(p.chain(p.good)); !errors.As(err, &re) || re.Serial.Cmp(p.inter.cert.SerialNumber) != 0 {
		t.Fatalf("leaf under a revoked intermediate: got %v", err)
	}
	// The chain without the root: the root is found among the sources.
	if err := c.CheckChain(p.chain(p.good)[:2]); !errors.Is(err, ErrRevoked) {
		t.Fatalf("chain without its root: got %v", err)
	}
	// Every verified chain must pass.
	other := newRoot(t, "Other Root")
	if err := c.CheckChains([][]*x509.Certificate{{p.good, other.cert}, p.chain(p.good)}); !errors.Is(err, ErrRevoked) {
		t.Fatalf("CheckChains: got %v", err)
	}
}

func TestWrongSigner(t *testing.T) {
	// The key identifier check refuses the impostor's CRL before its
	// signature is checked; the last subtest leaves it to the signature.
	p := newPKI(t)
	// An impostor with the intermediate's name but another key.
	impostor := p.root.newIntermediate(t, "Test Device CA")
	stranger := newRoot(t, "Stranger CA")
	for name, der := range map[string][]byte{
		"same name, other key": impostor.makeCRL(t, crlOpts{number: 5}),
		"other CA":             stranger.makeCRL(t, crlOpts{number: 5}),
	} {
		t.Run(name, func(t *testing.T) {
			c := mustNew(t, Config{DisableRefresh: true, Sources: fileSources(t, p, der, p.root.makeCRL(t, crlOpts{number: 1}), FailClosed)})
			st := c.Status()[0]
			if st.State != StateMissing || st.LastError == "" {
				t.Fatalf("status = %+v, want missing with an error", st)
			}
			if !strings.Contains(st.LastError, "signature") && !strings.Contains(st.LastError, "is not the CA") &&
				!strings.Contains(st.LastError, "key identifier") {
				t.Errorf("LastError %q", st.LastError)
			}
			if err := c.CheckChain(p.chain(p.good)); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("got %v, want ErrUnavailable", err)
			}
		})
	}

	// Without the key identifier the signature check must catch it.
	t.Run("same name, other key, no key identifier", func(t *testing.T) {
		issuer := *p.inter.cert
		issuer.SubjectKeyId = nil
		path := writeFile(t, t.TempDir(), "i.crl", impostor.makeCRL(t, crlOpts{number: 5}))
		c := mustNew(t, Config{DisableRefresh: true, Sources: []Source{{Issuer: &issuer, File: path}}})
		if st := c.Status()[0]; st.State != StateMissing || !strings.Contains(st.LastError, "signature") {
			t.Fatalf("status = %+v", st)
		}
	})
}

func TestStaleCRL(t *testing.T) {
	p := newPKI(t)
	old := crlOpts{number: 3, thisUpdate: time.Now().Add(-48 * time.Hour), nextUpdate: time.Now().Add(-time.Hour)}
	root := p.root.makeCRL(t, crlOpts{number: 1})

	c := mustNew(t, Config{DisableRefresh: true, Sources: fileSources(t, p, p.inter.makeCRL(t, old, p.bad), root, FailClosed)})
	st := c.Status()[0]
	if st.State != StateStale || !st.Stale || st.Revoked != 1 || st.Number.Int64() != 3 {
		t.Fatalf("status = %+v", st)
	}
	err := c.CheckChain(p.chain(p.good))
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("FailClosed, stale CRL: got %v", err)
	}

	c = mustNew(t, Config{DisableRefresh: true, Sources: fileSources(t, p, p.inter.makeCRL(t, old, p.bad), root, FailOpen)})
	if err := c.CheckChain(p.chain(p.good)); err != nil {
		t.Fatalf("FailOpen, stale CRL: got %v", err)
	}
	if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("FailOpen, stale CRL listing the leaf: got %v", err)
	}
}

func TestMissingCRL(t *testing.T) {
	p := newPKI(t)
	missing := filepath.Join(t.TempDir(), "absent.crl")
	for _, pol := range []Policy{FailClosed, FailOpen} {
		c := mustNew(t, Config{DisableRefresh: true, Sources: []Source{{Issuer: p.inter.cert, File: missing, Policy: pol}}})
		st := c.Status()[0]
		if st.State != StateMissing || !strings.Contains(st.LastError, "absent.crl") {
			t.Fatalf("%v: status = %+v", pol, st)
		}
		err := c.CheckChain(p.chain(p.good))
		if pol == FailClosed && !errors.Is(err, ErrUnavailable) {
			t.Fatalf("FailClosed: got %v", err)
		}
		if pol == FailOpen && err != nil {
			t.Fatalf("FailOpen: got %v", err)
		}
	}
}

func TestNotConfigured(t *testing.T) {
	p := newPKI(t)
	spare := newRoot(t, "Spare Root")
	dir := t.TempDir()
	c := mustNew(t, Config{
		DisableRefresh: true,
		Sources:        []Source{{Issuer: p.inter.cert, File: writeFile(t, dir, "i.crl", p.inter.makeCRL(t, crlOpts{number: 1}, p.bad))}},
		Unchecked:      []*x509.Certificate{spare.cert},
	})
	if err := c.CheckChain(p.chain(p.good)); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v", err)
	}
	st := c.Status()
	if len(st) != 3 {
		t.Fatalf("status has %d entries: %+v", len(st), st)
	}
	names := []string{st[1].Name, st[2].Name}
	for i, want := range []string{spare.cert.Subject.String(), p.root.cert.Subject.String()} {
		if names[i] != want || st[i+1].State != StateNotConfigured {
			t.Errorf("status[%d] = %+v, want %q not configured", i+1, st[i+1], want)
		}
	}
}

func TestRefreshAndRollback(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	path := writeFile(t, dir, "inter.crl", p.inter.makeCRL(t, crlOpts{number: 1}))
	var mu sync.Mutex
	var kinds []EventKind
	c := mustNew(t, Config{
		DisableRefresh: true,
		Sources:        []Source{{Issuer: p.inter.cert, File: path}},
		OnEvent: func(e Event) {
			mu.Lock()
			kinds = append(kinds, e.Kind)
			mu.Unlock()
		},
	})
	if err := c.CheckChain(p.chain(p.bad)); err != nil {
		t.Fatalf("before the refresh: %v", err)
	}

	writeFile(t, dir, "inter.crl", pemCRL(p.inter.makeCRL(t, crlOpts{number: 2}, p.bad)))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after the refresh: %v", err)
	}

	// The same number again is the same CRL.
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A lower number is a rollback, even if signed by the CA.
	writeFile(t, dir, "inter.crl", p.inter.makeCRL(t, crlOpts{number: 1}))
	err := c.Refresh(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("rollback: got %v", err)
	}
	if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("after the refused rollback: %v", err)
	}
	st := c.Status()[0]
	if st.Number.Int64() != 2 || st.State != StateOK || !strings.Contains(st.LastError, "rollback") {
		t.Fatalf("status = %+v", st)
	}

	// A CRL without a number cannot replace a numbered one.
	writeFile(t, dir, "inter.crl", p.inter.makeUnnumberedCRL(t, time.Now()))
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("unnumbered CRL replaced a numbered one")
	}

	mu.Lock()
	defer mu.Unlock()
	// Refreshes only; the checks add EventRevoked in between.
	want := []EventKind{EventLoaded, EventLoaded, EventUnchanged, EventRefreshFailed, EventRefreshFailed}
	var got []EventKind
	for _, k := range kinds {
		if k != EventRevoked {
			got = append(got, k)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("events %v, want %v", kinds, want)
	}
}

func TestUnnumberedCRLs(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	now := time.Now()
	path := writeFile(t, dir, "i.crl", p.inter.makeUnnumberedCRL(t, now.Add(-time.Hour)))
	c := mustNew(t, Config{DisableRefresh: true, Sources: []Source{{Issuer: p.inter.cert, File: path}}})
	writeFile(t, dir, "i.crl", p.inter.makeUnnumberedCRL(t, now.Add(-time.Minute), p.bad))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "i.crl", p.inter.makeUnnumberedCRL(t, now.Add(-2*time.Hour)))
	if err := c.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "rollback") {
		t.Fatalf("older thisUpdate: got %v", err)
	}
	if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v", err)
	}
}

func TestBackgroundRefresh(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	path := writeFile(t, dir, "i.crl", p.inter.makeCRL(t, crlOpts{number: 1}))
	c := mustNew(t, Config{
		Sources:         []Source{{Issuer: p.inter.cert, File: path}},
		RefreshInterval: 20 * time.Millisecond,
		RetryMin:        10 * time.Millisecond,
		RetryMax:        20 * time.Millisecond,
	})
	writeFile(t, dir, "i.crl", p.inter.makeCRL(t, crlOpts{number: 2}, p.bad))
	deadline := time.Now().Add(10 * time.Second)
	for !errors.Is(c.CheckChain(p.chain(p.bad)), ErrRevoked) {
		if time.Now().After(deadline) {
			t.Fatalf("background refresh did not load the new CRL: %+v", c.Status()[0])
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.Close()
	c.Close() // idempotent
	// After Close, checks still use the last CRL and nothing refreshes.
	writeFile(t, dir, "i.crl", p.inter.makeCRL(t, crlOpts{number: 3}))
	last := c.Status()[0].LastFetch
	time.Sleep(60 * time.Millisecond)
	if st := c.Status()[0]; !st.LastFetch.Equal(last) || st.Number.Int64() != 2 {
		t.Fatalf("refreshed after Close: %+v", st)
	}
}

func TestNextRefresh(t *testing.T) {
	cfg := &Config{RefreshInterval: time.Hour, RefreshMargin: 10 * time.Minute, RetryMin: time.Minute, RetryMax: 8 * time.Minute}
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		next    time.Time // CRL nextUpdate; zero: no CRL
		backoff int
		want    time.Duration
	}{
		{"periodic", now.Add(24 * time.Hour), 0, time.Hour},
		{"no CRL yet", time.Time{}, 0, time.Hour},
		{"before nextUpdate", now.Add(30 * time.Minute), 0, 20 * time.Minute},
		{"inside the margin", now.Add(5 * time.Minute), 0, time.Minute},
		{"first failure", now.Add(24 * time.Hour), 1, time.Minute},
		{"third failure", now.Add(24 * time.Hour), 3, 4 * time.Minute},
		{"capped", now.Add(24 * time.Hour), 40, 8 * time.Minute},
	}
	for _, tc := range cases {
		var l *crl
		if !tc.next.IsZero() {
			l = &crl{nextUpdate: tc.next}
		}
		if got := nextRefresh(now, l, tc.backoff, cfg).Sub(now); got != tc.want {
			t.Errorf("%s: next refresh in %v, want %v", tc.name, got, tc.want)
		}
	}
}

// idpExt encodes an issuing distribution point extension (RFC 5280
// 5.2.5; implicit tags) with the given URIs and flags.
func idpExt(uris []string, onlyUser, onlyCA bool) pkix.Extension {
	var names []byte
	for _, u := range uris {
		names = append(names, tlv(0x86, []byte(u))...)
	}
	var body []byte
	if len(uris) > 0 {
		body = append(body, tlv(0xa0, tlv(0xa0, names))...)
	}
	if onlyUser {
		body = append(body, 0x81, 1, 0xff)
	}
	if onlyCA {
		body = append(body, 0x82, 1, 0xff)
	}
	return pkix.Extension{Id: oidIssuingDistPoint, Critical: true, Value: tlv(0x30, body)}
}

func tlv(tag byte, v []byte) []byte {
	if len(v) >= 128 {
		panic("tlv: long form not needed in these tests")
	}
	return append([]byte{tag, byte(len(v))}, v...)
}

func TestIssuingDistributionPoint(t *testing.T) {
	root := newRoot(t, "Root")
	inter := root.newIntermediate(t, "Partitioned CA")
	leaf1, _ := inter.newLeaf(t, "p1", "http://pki.example/p1.crl")
	leaf2, _ := inter.newLeaf(t, "p2", "http://pki.example/p2.crl")
	leaf3, _ := inter.newLeaf(t, "no-dp")
	dir := t.TempDir()
	p1 := writeFile(t, dir, "p1.crl", inter.makeCRL(t, crlOpts{number: 1, extra: []pkix.Extension{idpExt([]string{"http://pki.example/p1.crl"}, true, false)}}, leaf1))
	p2 := writeFile(t, dir, "p2.crl", inter.makeCRL(t, crlOpts{number: 1, extra: []pkix.Extension{idpExt([]string{"http://pki.example/p2.crl"}, false, false)}}))
	c := mustNew(t, Config{DisableRefresh: true, Sources: []Source{
		{Issuer: inter.cert, File: p1}, {Issuer: inter.cert, File: p2},
	}})
	if err := c.CheckChain([]*x509.Certificate{leaf1, inter.cert, root.cert}); !errors.Is(err, ErrRevoked) {
		t.Errorf("leaf in partition 1: got %v", err)
	}
	if err := c.CheckChain([]*x509.Certificate{leaf2, inter.cert, root.cert}); err != nil {
		t.Errorf("leaf in partition 2: got %v", err)
	}
	if err := c.CheckChain([]*x509.Certificate{leaf3, inter.cert, root.cert}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("leaf in no partition: got %v", err)
	}

	// A CRL for CA certificates only does not cover a leaf.
	caOnly := writeFile(t, dir, "ca.crl", inter.makeCRL(t, crlOpts{number: 1, extra: []pkix.Extension{idpExt(nil, false, true)}}))
	c = mustNew(t, Config{DisableRefresh: true, Sources: []Source{{Issuer: inter.cert, File: caOnly}}})
	if err := c.CheckChain([]*x509.Certificate{leaf2, inter.cert}); !errors.Is(err, ErrUnavailable) {
		t.Errorf("CA-only CRL: got %v", err)
	}
}

func TestRefusedCRLs(t *testing.T) {
	p := newPKI(t)
	cases := map[string]struct {
		opts crlOpts
		want string
	}{
		"delta":            {crlOpts{number: 2, extra: []pkix.Extension{{Id: oidDeltaCRLIndicator, Critical: true, Value: []byte{2, 1, 1}}}}, "delta"},
		"unknown critical": {crlOpts{number: 2, extra: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Critical: true, Value: []byte{5, 0}}}}, "critical"},
		"future":           {crlOpts{number: 2, thisUpdate: time.Now().Add(time.Hour)}, "future"},
		"reason partition": {crlOpts{number: 2, extra: []pkix.Extension{{Id: oidIssuingDistPoint, Critical: true, Value: tlv(0x30, []byte{0x83, 2, 7, 0x80})}}}, "onlySomeReasons"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path := writeFile(t, t.TempDir(), "i.crl", p.inter.makeCRL(t, tc.opts))
			c := mustNew(t, Config{DisableRefresh: true, Sources: []Source{{Issuer: p.inter.cert, File: path}}})
			if st := c.Status()[0]; st.State != StateMissing || !strings.Contains(st.LastError, tc.want) {
				t.Fatalf("status = %+v, want an error with %q", st, tc.want)
			}
		})
	}
}

func TestConfigErrors(t *testing.T) {
	p := newPKI(t)
	for name, cfg := range map[string]Config{
		"no issuer":      {Sources: []Source{{File: "x"}}},
		"file and URL":   {Sources: []Source{{Issuer: p.inter.cert, File: "x", URL: "http://x/"}}},
		"neither":        {Sources: []Source{{Issuer: p.inter.cert}}},
		"ftp":            {Sources: []Source{{Issuer: p.inter.cert, URL: "ftp://x/a.crl"}}},
		"bad policy":     {Sources: []Source{{Issuer: p.inter.cert, File: "x", Policy: 7}}},
		"negative":       {FetchTimeout: -1},
		"retry reversed": {RetryMin: time.Hour, RetryMax: time.Minute},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted the configuration", name)
		}
	}
}

func TestVerifyPeerCertificateRaw(t *testing.T) {
	p := newPKI(t)
	c := mustNew(t, Config{DisableRefresh: true, Sources: fileSources(t, p,
		p.inter.makeCRL(t, crlOpts{number: 1}, p.bad), p.root.makeCRL(t, crlOpts{number: 1}), FailClosed)})
	raw := [][]byte{p.bad.Raw, p.inter.cert.Raw}
	if err := c.VerifyPeerCertificate(raw, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("raw chain: got %v", err)
	}
	if err := c.VerifyPeerCertificate(nil, [][]*x509.Certificate{p.chain(p.good)}); err != nil {
		t.Fatalf("verified chain: got %v", err)
	}
	if err := c.VerifyPeerCertificate(nil, nil); err != nil {
		t.Fatal(err)
	}
}

// TestConcurrent runs checks, refreshes and Status at once; run it with
// -race.
func TestConcurrent(t *testing.T) {
	p := newPKI(t)
	dir := t.TempDir()
	crls := make([][]byte, 20)
	for i := range crls {
		crls[i] = p.inter.makeCRL(t, crlOpts{number: int64(i + 1)}, p.bad)
	}
	path := writeFile(t, dir, "i.crl", crls[0])
	c := mustNew(t, Config{
		Sources:         []Source{{Issuer: p.inter.cert, File: path}},
		RefreshInterval: time.Millisecond,
		RetryMin:        time.Millisecond,
		RetryMax:        time.Millisecond,
	})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if err := c.CheckChain(p.chain(p.good)); err != nil {
					t.Error(err)
					return
				}
				if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
					t.Errorf("got %v", err)
					return
				}
				_ = c.Status()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, der := range crls[1:] {
			writeFile(t, dir, "i.crl", der)
			if err := c.Refresh(context.Background()); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
	if n := c.Status()[0].Number; n.Cmp(big.NewInt(20)) != 0 {
		t.Fatalf("final CRL number %v, want 20", n)
	}
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPSource(t *testing.T) {
	p := newPKI(t)
	var body atomic.Value
	body.Store(p.inter.makeCRL(t, crlOpts{number: 1}))
	var status atomic.Int32
	status.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/inter.crl" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(int(status.Load()))
		w.Write(body.Load().([]byte))
	}))
	defer srv.Close()

	c := mustNew(t, Config{DisableRefresh: true, HTTPClient: srv.Client(),
		Sources: []Source{{Issuer: p.inter.cert, URL: srv.URL + "/inter.crl"}}})
	if err := c.CheckChain(p.chain(p.bad)); err != nil {
		t.Fatal(err)
	}
	body.Store(p.inter.makeCRL(t, crlOpts{number: 2}, p.bad))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
		t.Fatalf("got %v", err)
	}

	// An error status keeps the last good CRL.
	status.Store(http.StatusServiceUnavailable)
	if err := c.Refresh(context.Background()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("503: got %v", err)
	}
	if st := c.Status()[0]; st.Number.Int64() != 2 || st.State != StateOK || st.LastError == "" {
		t.Fatalf("status = %+v", st)
	}

	// A 404 on a new checker: no CRL at all.
	c2 := mustNew(t, Config{DisableRefresh: true, HTTPClient: srv.Client(),
		Sources: []Source{{Issuer: p.inter.cert, URL: srv.URL + "/missing.crl"}}})
	if err := c2.CheckChain(p.chain(p.good)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("404: got %v", err)
	}
}

func TestHTTPSizeLimit(t *testing.T) {
	p := newPKI(t)
	der := p.inter.makeCRL(t, crlOpts{number: 1}, p.bad, p.good)
	for _, chunked := range []bool{false, true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if chunked {
				// No Content-Length: the limit applies while reading.
				w.Write(der[:10])
				w.(http.Flusher).Flush()
				w.Write(der[10:])
				return
			}
			w.Write(der)
		}))
		c := mustNew(t, Config{DisableRefresh: true, MaxCRLSize: int64(len(der) - 1),
			Sources: []Source{{Issuer: p.inter.cert, URL: srv.URL}}})
		st := c.Status()[0]
		if st.State != StateMissing || !strings.Contains(st.LastError, "exceeds the limit") {
			t.Errorf("chunked=%v: status = %+v", chunked, st)
		}
		if err := c.CheckChain(p.chain(p.good)); !errors.Is(err, ErrUnavailable) {
			t.Errorf("chunked=%v: got %v", chunked, err)
		}
		// Exactly at the limit is accepted.
		c = mustNew(t, Config{DisableRefresh: true, MaxCRLSize: int64(len(der)),
			Sources: []Source{{Issuer: p.inter.cert, URL: srv.URL}}})
		if err := c.CheckChain(p.chain(p.bad)); !errors.Is(err, ErrRevoked) {
			t.Errorf("chunked=%v, at the limit: got %v", chunked, err)
		}
		srv.Close()
	}
}

func TestHTTPTimeout(t *testing.T) {
	p := newPKI(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	start := time.Now()
	c := mustNew(t, Config{DisableRefresh: true, FetchTimeout: 100 * time.Millisecond,
		Sources: []Source{{Issuer: p.inter.cert, URL: srv.URL}}})
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("New took %v", d)
	}
	if st := c.Status()[0]; st.State != StateMissing || st.LastError == "" {
		t.Fatalf("status = %+v", st)
	}
}

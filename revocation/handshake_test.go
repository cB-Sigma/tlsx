// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/cB-Abhinav-Gautam/tlsx"
)

// handshake runs one TLS handshake over loopback TCP and returns the
// server's handshake error. stack is "crypto/tls" or "tlsx"; the client
// presents leaf and the intermediate; the server checks revocation in
// VerifyConnection.
func handshake(t *testing.T, stack string, version uint16, p *pki, chk *Checker, leaf *x509.Certificate, key *ecdsa.PrivateKey) error {
	t.Helper()
	srvLeaf, srvKey := p.inter.newLeaf(t, "server")
	roots := x509.NewCertPool()
	roots.AddCert(p.root.cert)
	cliChain := [][]byte{leaf.Raw, p.inter.cert.Raw}
	srvChain := [][]byte{srvLeaf.Raw, p.inter.cert.Raw}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		switch stack {
		case "crypto/tls":
			s := tls.Server(conn, &tls.Config{
				Certificates:     []tls.Certificate{{Certificate: srvChain, PrivateKey: srvKey}},
				ClientAuth:       tls.RequireAndVerifyClientCert,
				ClientCAs:        roots,
				MinVersion:       version,
				MaxVersion:       version,
				VerifyConnection: chk.VerifyConnection,
			})
			srvErr <- s.Handshake()
		case "tlsx":
			s := tlsx.Server(conn, &tlsx.Config{
				Certificates: []tlsx.Certificate{{Certificate: srvChain, PrivateKey: srvKey}},
				ClientAuth:   tlsx.RequireAndVerifyClientCert,
				ClientCAs:    roots,
				MinVersion:   version,
				MaxVersion:   version,
				VerifyConnection: func(cs tlsx.ConnectionState) error {
					return chk.CheckChains(cs.VerifiedChains)
				},
			})
			srvErr <- s.Handshake()
		}
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	// The client is always crypto/tls; the stack under test is the server.
	c := tls.Client(conn, &tls.Config{
		Certificates: []tls.Certificate{{Certificate: cliChain, PrivateKey: key}},
		RootCAs:      roots,
		ServerName:   "localhost",
		MinVersion:   version,
		MaxVersion:   version,
	})
	cliErr := c.Handshake()
	if cliErr == nil && version == tls.VersionTLS13 {
		// In TLS 1.3 the client finishes before the server has checked
		// its certificate; the refusal arrives as an alert on read.
		_, cliErr = c.Read(make([]byte, 1))
	}
	err = <-srvErr
	if err != nil && cliErr == nil {
		t.Errorf("server refused (%v) but the client saw no error", err)
	}
	return err
}

// TestHandshake refuses a revoked client certificate through
// VerifyConnection in TLS 1.2 and 1.3, with crypto/tls and with tlsx.
func TestHandshake(t *testing.T) {
	p := newPKI(t)
	chk := mustNew(t, Config{DisableRefresh: true, Sources: fileSources(t, p,
		p.inter.makeCRL(t, crlOpts{number: 1}, p.bad), p.root.makeCRL(t, crlOpts{number: 1}), FailClosed)})
	for _, stack := range []string{"crypto/tls", "tlsx"} {
		for _, v := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
			t.Run(fmt.Sprintf("%s/%s", stack, tls.VersionName(v)), func(t *testing.T) {
				if err := handshake(t, stack, v, p, chk, p.good, p.goodKey); err != nil {
					t.Fatalf("unrevoked client refused: %v", err)
				}
				err := handshake(t, stack, v, p, chk, p.bad, p.badKey)
				if !errors.Is(err, ErrRevoked) {
					t.Fatalf("revoked client: server error %v, want ErrRevoked", err)
				}
			})
		}
	}
}

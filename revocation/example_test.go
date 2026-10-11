// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation_test

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"time"

	"github.com/cB-Sigma/tlsx"
	"github.com/cB-Sigma/tlsx/revocation"
)

var deviceCA, rootCA *x509.Certificate // the trusted CAs, loaded elsewhere
var clientCAs *x509.CertPool

// A crypto/tls server that refuses revoked client certificates.
func Example() {
	chk, err := revocation.New(revocation.Config{
		Sources: []revocation.Source{
			// FailClosed (the default): no usable CRL, no connection.
			{Issuer: deviceCA, URL: "http://pki.example/device-ca.crl"},
			// FailOpen must be chosen explicitly.
			{Issuer: rootCA, File: "/etc/pki/root.crl", Policy: revocation.FailOpen},
		},
		RefreshInterval: 30 * time.Minute,
		OnEvent: func(e revocation.Event) {
			if e.Err != nil {
				log.Printf("revocation %s: %s: %v", e.Kind, e.Source, e.Err)
			}
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer chk.Close()

	cfg := &tls.Config{
		ClientAuth:       tls.RequireAndVerifyClientCert,
		ClientCAs:        clientCAs,
		VerifyConnection: chk.VerifyConnection,
	}
	_ = cfg

	for _, s := range chk.Status() {
		log.Printf("%s: %s, next update %s, %d revoked, error %q",
			s.Name, s.State, s.NextUpdate, s.Revoked, s.LastError)
	}
}

// The same check with tlsx, whose ConnectionState is its own type.
func Example_tlsx() {
	chk, err := revocation.New(revocation.Config{
		Sources: []revocation.Source{{Issuer: deviceCA, File: "/etc/pki/device-ca.crl"}},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer chk.Close()

	cfg := &tlsx.Config{
		ClientAuth: tlsx.RequireAndVerifyClientCert,
		ClientCAs:  clientCAs,
		VerifyConnection: func(cs tlsx.ConnectionState) error {
			return chk.CheckChains(cs.VerifiedChains)
		},
	}
	_ = cfg
}

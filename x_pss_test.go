// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// An id-RSASSA-PSS key may only make rsa_pss_pss signatures. BoGo's
// CertificateCipherMismatch-PSS and RejectPSSKeyType-* tests found that
// tlsx accepted such a key for RSA key transport and for rsa_pss_rsae,
// PKCS #1 v1.5 and TLS 1.0/1.1 signatures.

// pssImpostor is a Certificate that sends the PSS test certificate but
// whose Leaf is an rsaEncryption certificate for the same key, so that
// tlsx itself signs with the key as an ordinary RSA key: a peer that
// misuses its PSS key.
func pssImpostor(t *testing.T) Certificate {
	t.Helper()
	p := testPKI(t)
	key := p.pss.cert.PrivateKey.(*rsa.PrivateKey)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(9001), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.caCert, key.Public(), p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if IsRSAPSSKey(leaf) {
		t.Fatal("an rsaEncryption certificate for a PSS certificate's key is taken for a PSS key")
	}
	c := p.pss.cert
	c.Leaf = leaf
	return c
}

func TestRSAPSSKeyRestrictions(t *testing.T) {
	p := testPKI(t)
	impostor := pssImpostor(t)

	t.Run("server does not use a PSS key for RSA key transport", func(t *testing.T) {
		cc, sc := xConfigs(t, p.pss)
		cc.Certificates, sc.ClientAuth = nil, NoClientCert
		cc.MaxVersion = VersionTLS12
		cc.CipherSuites = []uint16{TLS_RSA_WITH_AES_128_GCM_SHA256}
		sc.CipherSuites = cc.CipherSuites
		_, server, _ := xPair(t, cc, sc)
		if err := server.Handshake(); err == nil || !strings.Contains(err.Error(), "no cipher suite") {
			t.Fatalf("got %v, want no shared cipher suite", err)
		}
	})

	t.Run("client does not encrypt to a PSS key", func(t *testing.T) {
		_, _, err := rsaKeyAgreement{}.generateClientKeyExchange(&Config{}, &clientHelloMsg{vers: VersionTLS12}, p.pss.x509)
		if err == nil || !strings.Contains(err.Error(), "RSASSA-PSS") {
			t.Fatalf("got %v, want a refusal", err)
		}
	})

	for _, v := range []uint16{VersionTLS10, VersionTLS11, VersionTLS12} {
		t.Run("client refuses a server's PSS key misused in "+VersionName(v), func(t *testing.T) {
			cc, sc := xConfigs(t, p.pss)
			cc.Certificates, sc.ClientAuth = nil, NoClientCert
			cc.MinVersion, cc.MaxVersion, sc.MinVersion = v, v, VersionTLS10
			sc.Certificates = []Certificate{impostor}
			_, _, err := xPair(t, cc, sc)
			if err == nil || !strings.Contains(err.Error(), "RSASSA-PSS") {
				t.Fatalf("got %v, want a refusal of the PSS key", err)
			}
		})
		t.Run("server refuses a client's PSS key misused in "+VersionName(v), func(t *testing.T) {
			cc, sc := xConfigs(t, p.rsa)
			cc.MinVersion, cc.MaxVersion, sc.MinVersion = v, v, VersionTLS10
			cc.Certificates = []Certificate{impostor}
			_, server, _ := xPair(t, cc, sc)
			err := server.Handshake()
			if err == nil || !strings.Contains(err.Error(), "RSASSA-PSS") {
				t.Fatalf("got %v, want a refusal of the PSS key", err)
			}
		})
	}

	t.Run("server does not sign with a PSS key in TLS 1.0 and 1.1", func(t *testing.T) {
		cc, sc := xConfigs(t, p.pss)
		cc.Certificates, sc.ClientAuth = nil, NoClientCert
		cc.MinVersion, cc.MaxVersion, sc.MinVersion = VersionTLS11, VersionTLS11, VersionTLS10
		_, server, _ := xPair(t, cc, sc)
		if err := server.Handshake(); err == nil || !strings.Contains(err.Error(), "no cipher suite") {
			t.Fatalf("got %v, want no usable cipher suite", err)
		}
	})
}

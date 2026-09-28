// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"testing"
	"time"
)

func staticDHCert(t *testing.T) (Certificate, *DHPrivateKey) {
	t.Helper()
	p := testPKI(t)
	key, err := GenerateStaticDHKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageKeyAgreement, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := CreateStaticDHCertificate(rand.Reader, tpl, p.caCert, &key.DHPublicKey, p.caKey)
	if err != nil {
		t.Fatal(err)
	}
	return Certificate{Certificate: [][]byte{der, p.caCert.Raw}, PrivateKey: key}, key
}

func TestStaticDHSuite(t *testing.T) {
	// Off by default.
	if slices.Contains(defaultCipherSuites(true), TLS_DH_RSA_WITH_AES_128_GCM_SHA256) {
		t.Fatal("static DH offered by default")
	}
	if n := CipherSuiteName(TLS_DH_RSA_WITH_AES_128_GCM_SHA256); n != "TLS_DH_RSA_WITH_AES_128_GCM_SHA256" {
		t.Fatalf("name %q", n)
	}
	p := testPKI(t)
	dhCert, key := staticDHCert(t)
	cc, sc := xConfigs(t, p.ecdsa)
	cc.MaxVersion = VersionTLS12
	cc.CipherSuites = []uint16{TLS_DH_RSA_WITH_AES_128_GCM_SHA256}
	sc.CipherSuites = []uint16{TLS_DH_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
	sc.Ext.StaticDHCertificate = &dhCert
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	go echo(server)
	roundTrip(t, client, "static dh")
	st := client.ConnectionState()
	if st.CipherSuite != TLS_DH_RSA_WITH_AES_128_GCM_SHA256 || st.Version != VersionTLS12 {
		t.Fatalf("%s", CipherSuiteName(st.CipherSuite))
	}
	pub, ok := st.PeerCertificates[0].PublicKey.(*DHPublicKey)
	if !ok || pub.Y.Cmp(key.Y) != 0 {
		t.Fatal("the server certificate's DH key")
	}
	if len(server.ConnectionState().PeerCertificates) == 0 {
		t.Fatal("client authentication with static DH")
	}
	// A server without a DH certificate does not select it.
	sc.Ext.StaticDHCertificate = nil
	if _, _, err := xPair(t, cc, sc); err == nil {
		t.Fatal("static DH without a DH certificate")
	}
	// A DH certificate is refused for any other suite.
	sc2 := sc.Clone()
	sc2.Certificates = []Certificate{dhCert}
	sc2.CipherSuites = nil
	cc2 := cc.Clone()
	cc2.CipherSuites = nil
	if _, _, err := xPair(t, cc2, sc2); err == nil {
		t.Fatal("a DH certificate accepted with an ECDHE suite")
	}
	// The key encodes as PKCS #8 and reads back.
	der, err := MarshalStaticDHKey(key)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseStaticDHKey(der)
	if err != nil || back.X.Cmp(key.X) != 0 || back.Y.Cmp(key.Y) != 0 {
		t.Fatalf("PKCS #8: %v", err)
	}
	// Small or out-of-range values are refused.
	small := &DHPublicKey{P: big.NewInt(23), G: big.NewInt(5), Y: big.NewInt(8)}
	if small.check(small.Y) == nil {
		t.Fatal("a 5-bit modulus accepted")
	}
	if key.check(big.NewInt(1)) == nil || key.check(new(big.Int).Sub(key.P, big.NewInt(1))) == nil {
		t.Fatal("y = 1 or p-1 accepted")
	}
}

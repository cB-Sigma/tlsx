// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
)

// A PKCS #10 request signed with a brainpool key carries the brainpool
// SubjectPublicKeyInfo, verifies, and a tampered one does not; a request
// for another key type goes through crypto/x509 unchanged (F-1024).
func TestCreateCertificateRequest(t *testing.T) {
	for _, c := range []elliptic.Curve{P256r1(), P384r1(), P512r1()} {
		k, err := GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		der, err := CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "station-22"}, DNSNames: []string{"rtu22.example"}}, k)
		if err != nil {
			t.Fatalf("%s: %v", c.Params().Name, err)
		}
		req, err := ParseCertificateRequest(der)
		if err != nil {
			t.Fatalf("%s: %v", c.Params().Name, err)
		}
		pub, ok := req.PublicKey.(*ecdsa.PublicKey)
		if !ok || !pub.Equal(k.Public()) || req.Subject.CommonName != "station-22" || len(req.DNSNames) != 1 {
			t.Errorf("%s: parsed %+v", c.Params().Name, req)
		}
		spki, _ := MarshalPKIXPublicKey(k.Public().(*ecdsa.PublicKey))
		if string(req.RawSubjectPublicKeyInfo) != string(spki) {
			t.Errorf("%s: the request does not carry the brainpool key", c.Params().Name)
		}
		bad := append([]byte(nil), der...)
		bad[len(bad)/3] ^= 0x01
		if _, err := ParseCertificateRequest(bad); err == nil {
			t.Errorf("%s: a tampered request verifies", c.Params().Name)
		}
	}
	p, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "p256"}}, p)
	if err != nil {
		t.Fatal(err)
	}
	if req, err := x509.ParseCertificateRequest(der); err != nil || req.CheckSignature() != nil {
		t.Errorf("P-256 request: %v", err)
	}
}

// OpenSSL verifies the request's signature and reads its brainpool key.
func TestCreateCertificateRequestOpenSSL(t *testing.T) {
	ossl := opensslPath(t)
	dir := t.TempDir()
	k, err := GenerateKey(P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "station-22"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, dir+"/req.pem", "CERTIFICATE REQUEST", der)
	out := string(runOpenSSL(t, ossl, dir, "req", "-in", "req.pem", "-verify", "-noout", "-text"))
	if !strings.Contains(out, "brainpoolP256r1") || !strings.Contains(out, "station-22") {
		t.Errorf("openssl reads %s", out)
	}
}

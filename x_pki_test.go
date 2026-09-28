// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/brainpool"
)

// Test PKI for the tlsx tests: one RSA CA issuing RSA, ECDSA P-256,
// RSASSA-PSS and brainpool leaves for "localhost".

type xLeaf struct {
	cert    Certificate
	certPEM []byte
	keyPEM  []byte
	x509    *x509.Certificate
}

type xPKI struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	caPEM  []byte
	pool   *x509.CertPool
	rsa    xLeaf
	ecdsa  xLeaf
	pss    xLeaf
	bp256  xLeaf
	client xLeaf
}

var (
	xPKIOnce sync.Once
	xPKIVal  *xPKI
	xPKIErr  error
)

func testPKI(t testing.TB) *xPKI {
	t.Helper()
	xPKIOnce.Do(func() { xPKIVal, xPKIErr = newXPKI() })
	if xPKIErr != nil {
		t.Fatal(xPKIErr)
	}
	return xPKIVal
}

func newXPKI() (*xPKI, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tlsx test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		return nil, err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	p := &xPKI{caCert: caCert, caKey: caKey, caPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), pool: x509.NewCertPool()}
	p.pool.AddCert(caCert)
	serial := int64(2)
	tmpl := func(cn string) *x509.Certificate {
		serial++
		return &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			DNSNames:    []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		}
	}
	mk := func(der []byte, key crypto.PrivateKey, keyDER []byte, keyType string) (xLeaf, error) {
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: keyType, Bytes: keyDER})
		c, err := X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return xLeaf{}, err
		}
		c.Certificate = append(c.Certificate, caDER)
		leaf, err := ParseCertificate(der)
		return xLeaf{cert: c, certPEM: certPEM, keyPEM: keyPEM, x509: leaf}, err
	}

	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err := x509.CreateCertificate(rand.Reader, tmpl("localhost"), caCert, rk.Public(), caKey)
	if err != nil {
		return nil, err
	}
	if p.rsa, err = mk(der, rk, x509.MarshalPKCS1PrivateKey(rk), "RSA PRIVATE KEY"); err != nil {
		return nil, err
	}

	ck, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err = x509.CreateCertificate(rand.Reader, tmpl("client"), caCert, ck.Public(), caKey)
	if err != nil {
		return nil, err
	}
	if p.client, err = mk(der, ck, x509.MarshalPKCS1PrivateKey(ck), "RSA PRIVATE KEY"); err != nil {
		return nil, err
	}

	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err = x509.CreateCertificate(rand.Reader, tmpl("localhost"), caCert, ek.Public(), caKey)
	if err != nil {
		return nil, err
	}
	ekDER, _ := x509.MarshalECPrivateKey(ek)
	if p.ecdsa, err = mk(der, ek, ekDER, "EC PRIVATE KEY"); err != nil {
		return nil, err
	}

	pk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, err = pssCertificate(tmpl("localhost"), caCert, caKey, pk)
	if err != nil {
		return nil, err
	}
	if p.pss, err = mk(der, pk, pssPKCS8(pk), "PRIVATE KEY"); err != nil {
		return nil, err
	}

	bk, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err = brainpool.CreateCertificate(rand.Reader, tmpl("localhost"), caCert, bk.Public(), caKey)
	if err != nil {
		return nil, err
	}
	bkDER, err := brainpool.MarshalPKCS8PrivateKey(bk)
	if err != nil {
		return nil, err
	}
	if p.bp256, err = mk(der, bk, bkDER, "PRIVATE KEY"); err != nil {
		return nil, err
	}
	return p, nil
}

// pssCertificate issues a certificate whose key is an RSASSA-PSS key (OID
// id-RSASSA-PSS, no parameters): crypto/x509 cannot, so the TBS it makes
// for the RSA key gets its SubjectPublicKeyInfo replaced and is signed
// again.
func pssCertificate(tmpl, parent *x509.Certificate, signer crypto.Signer, key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), signer)
	if err != nil {
		return nil, err
	}
	var cert struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, err
	}
	var tbs []asn1.RawValue
	var rest = cert.TBS.Bytes
	for len(rest) > 0 {
		var v asn1.RawValue
		if rest, err = asn1.Unmarshal(rest, &v); err != nil {
			return nil, err
		}
		tbs = append(tbs, v)
	}
	// Fields: [0]version, serial, sigalg, issuer, validity, subject, spki, ...
	if len(tbs) < 7 {
		return nil, errors.New("short TBS")
	}
	spkiDER, err := asn1.Marshal(spki{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSASSAPSS},
		PublicKey: asn1.BitString{Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey), BitLength: 8 * len(x509.MarshalPKCS1PublicKey(&key.PublicKey))},
	})
	if err != nil {
		return nil, err
	}
	tbs[6] = asn1.RawValue{FullBytes: spkiDER}
	var body []byte
	for _, v := range tbs {
		body = append(body, v.FullBytes...)
	}
	newTBS, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body})
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(newTBS)
	var opts crypto.SignerOpts = crypto.SHA256
	if tmpl.SignatureAlgorithm == x509.SHA256WithRSAPSS {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}
	}
	sig, err := signer.Sign(rand.Reader, h[:], opts)
	if err != nil {
		return nil, err
	}
	out, err := asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg asn1.RawValue
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: newTBS}, cert.SigAlg, asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)}})
	return out, err
}

// pssPKCS8 wraps an RSA key as a PKCS#8 RSASSA-PSS private key.
func pssPKCS8(k *rsa.PrivateKey) []byte {
	b, err := asn1.Marshal(pkcs8{Version: 0, Algo: pkix.AlgorithmIdentifier{Algorithm: oidRSASSAPSS}, PrivateKey: x509.MarshalPKCS1PrivateKey(k)})
	if err != nil {
		panic(err)
	}
	return b
}

// writeFiles writes name → contents into dir and returns the paths.
func writeFiles(t testing.TB, files map[string][]byte) map[string]string {
	t.Helper()
	dir := t.TempDir()
	out := map[string]string{}
	for name, b := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		out[name] = p
	}
	return out
}

// xConfigs returns a client and a server configuration over the test PKI
// with mutual authentication.
func xConfigs(t testing.TB, leaf xLeaf) (client, server *Config) {
	p := testPKI(t)
	client = &Config{RootCAs: p.pool, ServerName: "localhost", Certificates: []Certificate{p.client.cert}, MinVersion: VersionTLS12}
	server = &Config{Certificates: []Certificate{leaf.cert}, ClientCAs: p.pool, ClientAuth: RequireAndVerifyClientCert, MinVersion: VersionTLS12}
	return client, server
}

// xPair runs a handshake over a loopback TCP pair and returns both ends.
func xPair(t *testing.T, clientCfg, serverCfg *Config) (client, server *Conn, err error) {
	t.Helper()
	c, s := localPipe(t)
	client, server = Client(c, clientCfg), Server(s, serverCfg)
	t.Cleanup(func() { client.Close(); server.Close() })
	errc := make(chan error, 1)
	go func() { errc <- server.Handshake() }()
	cerr := client.Handshake()
	serr := <-errc
	if cerr != nil {
		return client, server, cerr
	}
	return client, server, serr
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The tests build their own PKI: a root, intermediates and leaves, all
// ECDSA P-256, and CRLs signed with crypto/x509.

type testCA struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func newKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func randSerial(t testing.TB) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

func issue(t testing.TB, tmpl *x509.Certificate, parent *testCA, key crypto.Signer) *x509.Certificate {
	t.Helper()
	signer, parentCert := key, tmpl
	if parent != nil {
		signer, parentCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func caTemplate(t testing.TB, cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"tlsx revocation test"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

func newRoot(t testing.TB, cn string) *testCA {
	t.Helper()
	k := newKey(t)
	return &testCA{cert: issue(t, caTemplate(t, cn), nil, k), key: k}
}

func (ca *testCA) newIntermediate(t testing.TB, cn string) *testCA {
	t.Helper()
	k := newKey(t)
	return &testCA{cert: issue(t, caTemplate(t, cn), ca, k), key: k}
}

// newLeaf issues a certificate usable by TLS clients and servers for
// "localhost". crlURIs become its CRL distribution points.
func (ca *testCA) newLeaf(t testing.TB, cn string, crlURIs ...string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		CRLDistributionPoints: crlURIs,
	}
	return issue(t, tmpl, ca, k), k
}

type crlOpts struct {
	number     int64 // crypto/x509 requires one; see makeUnnumberedCRL
	thisUpdate time.Time
	nextUpdate time.Time
	extra      []pkix.Extension
}

// makeCRL returns a DER CRL of ca listing revoked, current for a day
// unless opts says otherwise.
func (ca *testCA) makeCRL(t testing.TB, o crlOpts, revoked ...*x509.Certificate) []byte {
	t.Helper()
	if o.thisUpdate.IsZero() {
		o.thisUpdate = time.Now().Add(-time.Minute)
	}
	if o.nextUpdate.IsZero() {
		o.nextUpdate = o.thisUpdate.Add(24 * time.Hour)
	}
	tmpl := &x509.RevocationList{
		ThisUpdate:      o.thisUpdate,
		NextUpdate:      o.nextUpdate,
		ExtraExtensions: o.extra,
	}
	if o.number != 0 {
		tmpl.Number = big.NewInt(o.number)
	}
	for _, c := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   c.SerialNumber,
			RevocationTime: time.Now().Add(-30 * time.Second),
			ReasonCode:     1, // keyCompromise
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.cert, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func writeFile(t testing.TB, dir, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	// Write and rename, so a concurrent reader never sees a partial file.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func pemCRL(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

// pki is the usual test hierarchy: root -> inter -> leaves.
type pki struct {
	root, inter *testCA
	good, bad   *x509.Certificate
	goodKey     *ecdsa.PrivateKey
	badKey      *ecdsa.PrivateKey
}

func newPKI(t testing.TB) *pki {
	p := &pki{root: newRoot(t, "Test Root")}
	p.inter = p.root.newIntermediate(t, "Test Device CA")
	p.good, p.goodKey = p.inter.newLeaf(t, "device-good")
	p.bad, p.badKey = p.inter.newLeaf(t, "device-revoked")
	return p
}

func (p *pki) chain(leaf *x509.Certificate) []*x509.Certificate {
	return []*x509.Certificate{leaf, p.inter.cert, p.root.cert}
}

func mustNew(t testing.TB, cfg Config) *Checker {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// makeUnnumberedCRL returns a CRL of ca without a CRL number, current for
// a day from thisUpdate. crypto/x509 always writes a number, so this one
// is encoded with the pkix structures and signed here (ECDSA with SHA-256).
func (ca *testCA) makeUnnumberedCRL(t testing.TB, thisUpdate time.Time, revoked ...*x509.Certificate) []byte {
	t.Helper()
	algo := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	var issuer pkix.RDNSequence
	if _, err := asn1.Unmarshal(ca.cert.RawSubject, &issuer); err != nil {
		t.Fatal(err)
	}
	tbs := pkix.TBSCertificateList{
		Version:    1,
		Signature:  algo,
		Issuer:     issuer,
		ThisUpdate: thisUpdate.UTC().Truncate(time.Second),
		NextUpdate: thisUpdate.UTC().Truncate(time.Second).Add(24 * time.Hour),
	}
	for _, c := range revoked {
		tbs.RevokedCertificates = append(tbs.RevokedCertificates, pkix.RevokedCertificate{
			SerialNumber: c.SerialNumber, RevocationTime: thisUpdate.UTC().Truncate(time.Second)})
	}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(tbsDER)
	sig, err := ca.key.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(pkix.CertificateList{
		TBSCertList:        pkix.TBSCertificateList{Raw: tbsDER},
		SignatureAlgorithm: algo,
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: 8 * len(sig)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

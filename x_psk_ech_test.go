// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// Go 1.26.6 stopped sending pre_shared_key in the outer ClientHello of
// Encrypted Client Hello (the PSK belongs to the inner hello only). These
// tests check that rule for tlsx's TLS 1.3 external PSKs: pre_shared_key
// stays the last extension after the tlsx extensions, the outer hello never
// carries the external identity, and a client configured with both ECH
// and an external PSK does not leak the identity on the wire.

func externalPSKHello() *clientHelloMsg {
	return &clientHelloMsg{
		vers:               VersionTLS12,
		random:             make([]byte, 32),
		sessionId:          make([]byte, 32),
		cipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		supportedVersions:  []uint16{VersionTLS13},
		supportedCurves:    []CurveID{X25519},
		keyShares:          []keyShare{{group: X25519, data: make([]byte, 32)}},
		pskModes:           []uint8{pskModeDHE},
		pskIdentities:      []pskIdentity{{label: bytes.Clone(testPSKIdentity)}},
		pskBinders:         [][]byte{make([]byte, 32)},
		x:                  clientHelloExt{maxFragmentLength: 2, statusRequestV2: true},
	}
}

func TestExternalPSKECHPlacement(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ech      []byte
		echInner bool
		wantPSK  bool
	}{
		{"no ECH", nil, false, true},
		{"ECH inner hello", []byte{byte(innerECHExt)}, true, true},
		{"ECH inner marker, outer encoding", []byte{byte(innerECHExt)}, false, true},
		{"ECH outer hello", append([]byte{byte(outerECHExt)}, bytes.Repeat([]byte{7}, 40)...), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := externalPSKHello()
			m.encryptedClientHello = tc.ech
			b, err := m.marshalMsg(tc.echInner)
			if err != nil {
				t.Fatal(err)
			}
			var r clientHelloMsg
			if !r.unmarshal(b) {
				t.Fatal("ClientHello does not parse")
			}
			if got := len(r.pskIdentities) > 0; got != tc.wantPSK {
				t.Fatalf("pre_shared_key present %v, want %v", got, tc.wantPSK)
			}
			if !tc.wantPSK {
				if bytes.Contains(b, testPSKIdentity) {
					t.Fatal("outer ClientHello carries the external PSK identity")
				}
				return
			}
			if !bytes.Equal(r.pskIdentities[0].label, testPSKIdentity) || len(r.pskBinders) != 1 {
				t.Fatalf("identity %q binders %d", r.pskIdentities[0].label, len(r.pskBinders))
			}
			if last := r.extensions[len(r.extensions)-1]; last != extensionPreSharedKey {
				t.Fatalf("last extension %d, want pre_shared_key", last)
			}
		})
	}
}

// wireRecorder keeps what the client writes.
type wireRecorder struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (c *wireRecorder) Write(b []byte) (int, error) {
	c.mu.Lock()
	c.out.Write(b)
	c.mu.Unlock()
	return c.Conn.Write(b)
}

func TestExternalPSKNotSentWithECH(t *testing.T) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"public.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	publicDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	tmpl.DNSNames[0] = "secret.example"
	secretDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	secretCert, _ := x509.ParseCertificate(secretDER)

	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := cryptobyte.NewBuilder(nil)
	cfg.AddUint16(extensionEncryptedClientHello)
	cfg.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(1)
		b.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echKey.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(0x0001) // HKDF-SHA256
			b.AddUint16(0x0001) // AES-128-GCM
		})
		b.AddUint8(32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	echConfig := cfg.BytesOrPanic()
	list := cryptobyte.NewBuilder(nil)
	list.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echConfig) })

	client, server := psk13(false, false)
	client.ServerName = "secret.example"
	client.RootCAs = x509.NewCertPool()
	client.RootCAs.AddCert(secretCert)
	client.EncryptedClientHelloConfigList = list.BytesOrPanic()
	server.Certificates = []Certificate{
		{Certificate: [][]byte{publicDER}, PrivateKey: k},
		{Certificate: [][]byte{secretDER}, PrivateKey: k},
	}
	server.EncryptedClientHelloKeys = []EncryptedClientHelloKey{{Config: echConfig, PrivateKey: echKey.Bytes()}}

	cp, sp := localPipe(t)
	rec := &wireRecorder{Conn: cp}
	c, s := Client(rec, client), Server(sp, server)
	t.Cleanup(func() { c.Close(); s.Close() })
	errc := make(chan error, 1)
	go func() { errc <- s.Handshake() }()
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	cs := c.ConnectionState()
	if !cs.ECHAccepted || cs.Ext.PSKIdentity != nil || len(cs.PeerCertificates) == 0 {
		t.Fatalf("ECH %v, PSK identity %q, %d certificates", cs.ECHAccepted, cs.Ext.PSKIdentity, len(cs.PeerCertificates))
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if bytes.Contains(rec.out.Bytes(), testPSKIdentity) {
		t.Fatal("the client sent the external PSK identity in clear")
	}
}

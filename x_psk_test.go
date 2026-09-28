// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

var (
	testPSKIdentity = []byte("tlsx-test-psk-client-1")
	testPSKKey      = bytes.Repeat([]byte{0x5a}, 32)
)

func pskLookup(identity []byte) func(context.Context, []byte) ([]byte, error) {
	return func(_ context.Context, id []byte) ([]byte, error) {
		if bytes.Equal(id, identity) {
			return testPSKKey, nil
		}
		return nil, nil
	}
}

// pskServer has pre-shared keys only: no certificate at all.
func pskServer(suites ...uint16) *Config {
	return &Config{MinVersion: VersionTLS12, MaxVersion: VersionTLS12, CipherSuites: suites,
		Ext: ConfigExt{PSK: &PSKConfig{Hint: []byte("tlsx-hint"), Lookup: pskLookup(testPSKIdentity)}}}
}

func pskClient(suites ...uint16) *Config {
	return &Config{ServerName: "server.tlsx.test", MinVersion: VersionTLS12, MaxVersion: VersionTLS12, CipherSuites: suites,
		Ext: ConfigExt{PSK: &PSKConfig{Identity: testPSKIdentity, Key: testPSKKey}}}
}

func exchange(t *testing.T, c, s *Conn) {
	t.Helper()
	go func() { c.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := s.Read(buf); err != nil || string(buf) != "ping" {
		t.Fatalf("data: %q %v", buf, err)
	}
}

// Every TLS 1.2 PSK suite (RFC 4279, 5487, 5489, 6655, 7905, 8442) between
// a Go client and a Go server without certificates, among them
// TLS_PSK_WITH_AES_128_CBC_SHA256 that TS-0003 v4.8.1 clause 10.2.2 makes
// mandatory for the pre-shared key frameworks over TLS. The server learns
// the identity, the client the hint.
func TestPSKTLS12AllSuites(t *testing.T) {
	for id, name := range pskSuiteNames {
		t.Run(name, func(t *testing.T) {
			scfg, ccfg := pskServer(id), pskClient(id)
			ccfg.CurvePreferences = []CurveID{X25519, CurveP256, FFDHE2048}
			scfg.CurvePreferences = []CurveID{X25519, CurveP256, FFDHE2048}
			c, s, err := xPair(t, ccfg, scfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, cs := range []ConnectionState{c.ConnectionState(), s.ConnectionState()} {
				if cs.CipherSuite != id || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) || len(cs.PeerCertificates) != 0 {
					t.Fatalf("suite %s identity %q certs %d", CipherSuiteName(cs.CipherSuite), cs.Ext.PSKIdentity, len(cs.PeerCertificates))
				}
			}
			if h := c.ConnectionState().Ext.PSKIdentityHint; string(h) != "tlsx-hint" {
				t.Errorf("hint %q", h)
			}
			exchange(t, c, s)
		})
	}
}

func TestPSKTLS12Refusals(t *testing.T) {
	s := TLS_PSK_WITH_AES_128_CBC_SHA256
	t.Run("unknown identity", func(t *testing.T) {
		ccfg := pskClient(s)
		ccfg.Ext.PSK.Identity = []byte("someone-else")
		_, _, err := xPair(t, ccfg, pskServer(s))
		if err == nil || !strings.Contains(err.Error(), "unknown PSK identity") {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		ccfg := pskClient(s)
		ccfg.Ext.PSK.Key = bytes.Repeat([]byte{1}, 32)
		if _, _, err := xPair(t, ccfg, pskServer(s)); err == nil {
			t.Fatal("a wrong key completed the handshake")
		}
	})
	t.Run("client without a PSK does not offer the suites", func(t *testing.T) {
		ccfg := pskClient(s)
		ccfg.Ext.PSK = nil
		if _, _, err := xPair(t, ccfg, pskServer(s)); err == nil {
			t.Fatal("handshake without a PSK")
		}
	})
	t.Run("ClientKey chooses by hint", func(t *testing.T) {
		ccfg := pskClient(s)
		var hint atomic.Value
		ccfg.Ext.PSK = &PSKConfig{ClientKey: func(h []byte) ([]byte, []byte, error) {
			hint.Store(string(h))
			return testPSKIdentity, testPSKKey, nil
		}}
		if _, _, err := xPair(t, ccfg, pskServer(s)); err != nil {
			t.Fatal(err)
		}
		if hint.Load() != "tlsx-hint" {
			t.Fatalf("hint %v", hint.Load())
		}
	})
	t.Run("lookup error", func(t *testing.T) {
		scfg := pskServer(s)
		scfg.Ext.PSK.Lookup = func(context.Context, []byte) ([]byte, error) { return nil, errors.New("key store down") }
		if _, _, err := xPair(t, pskClient(s), scfg); err == nil {
			t.Fatal("handshake with a failing lookup")
		}
	})
	t.Run("server with certificate and PSK keeps both", func(t *testing.T) {
		ccfg, scfg := xConfigs(t, testPKI(t).ecdsa)
		scfg.ClientAuth = NoClientCert
		scfg.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, s}
		scfg.Ext.PSK = &PSKConfig{Lookup: pskLookup(testPSKIdentity)}
		ccfg.MaxVersion = VersionTLS12
		ccfg.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}
		c, _, err := xPair(t, ccfg, scfg)
		if err != nil || c.ConnectionState().CipherSuite != TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 {
			t.Fatalf("certificate client: %v", err)
		}
		pc := pskClient(s)
		if _, _, err := xPair(t, pc, scfg); err != nil {
			t.Fatalf("PSK client: %v", err)
		}
	})
	t.Run("no session tickets", func(t *testing.T) {
		ccfg := pskClient(s)
		ccfg.ClientSessionCache = NewLRUClientSessionCache(4)
		for range 2 {
			c, _, err := xPair(t, ccfg, pskServer(s))
			if err != nil || c.ConnectionState().DidResume {
				t.Fatalf("err %v resumed %v", err, err == nil && c.ConnectionState().DidResume)
			}
		}
	})
}

func psk13(allowNoDHE, preferNoDHE bool) (client, server *Config) {
	client = &Config{ServerName: "server.tlsx.test", MinVersion: VersionTLS13,
		Ext: ConfigExt{PSK: &PSKConfig{Identity: testPSKIdentity, Key: testPSKKey, TLS13: true, AllowNoDHE: allowNoDHE}}}
	server = &Config{MinVersion: VersionTLS13,
		Ext: ConfigExt{PSK: &PSKConfig{Lookup: pskLookup(testPSKIdentity), TLS13: true, AllowNoDHE: allowNoDHE, PreferNoDHE: preferNoDHE}}}
	return
}

// TLS 1.3 external PSKs (RFC 8446 4.2.11 with RFC 9257): psk_dhe_ke,
// psk_ke, SHA-384 PSKs, a HelloRetryRequest, a server that does not know
// the identity falling back to its certificate, and no tickets.
func TestPSKTLS13External(t *testing.T) {
	t.Run("psk_dhe_ke without certificates", func(t *testing.T) {
		ccfg, scfg := psk13(false, false)
		c, s, err := xPair(t, ccfg, scfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, cs := range []ConnectionState{c.ConnectionState(), s.ConnectionState()} {
			if cs.Version != VersionTLS13 || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) || cs.DidResume || cs.CurveID == 0 {
				t.Fatalf("version %x identity %q resumed %v group %v", cs.Version, cs.Ext.PSKIdentity, cs.DidResume, cs.CurveID)
			}
		}
		exchange(t, c, s)
	})
	t.Run("psk_ke when preferred", func(t *testing.T) {
		ccfg, scfg := psk13(true, true)
		c, s, err := xPair(t, ccfg, scfg)
		if err != nil {
			t.Fatal(err)
		}
		if cs := c.ConnectionState(); cs.CurveID != 0 || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) {
			t.Fatalf("group %v identity %q", cs.CurveID, cs.Ext.PSKIdentity)
		}
		exchange(t, c, s)
	})
	t.Run("psk_dhe_ke when psk_ke is only allowed", func(t *testing.T) {
		ccfg, scfg := psk13(true, false)
		c, _, err := xPair(t, ccfg, scfg)
		if err != nil || c.ConnectionState().CurveID == 0 {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("SHA-384", func(t *testing.T) {
		ccfg, scfg := psk13(false, false)
		ccfg.Ext.PSK.Hash, scfg.Ext.PSK.Hash = crypto.SHA384, crypto.SHA384
		scfg.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256}
		c, _, err := xPair(t, ccfg, scfg)
		if err != nil || c.ConnectionState().CipherSuite != TLS_AES_256_GCM_SHA384 {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("HelloRetryRequest", func(t *testing.T) {
		ccfg, scfg := psk13(false, false)
		ccfg.CurvePreferences = []CurveID{X25519, CurveP256}
		scfg.CurvePreferences = []CurveID{CurveP256}
		c, _, err := xPair(t, ccfg, scfg)
		if err != nil || !c.ConnectionState().HelloRetryRequest || c.ConnectionState().Ext.PSKIdentity == nil {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("unknown identity falls back to the certificate", func(t *testing.T) {
		ccfg, scfg := xConfigs(t, testPKI(t).ecdsa)
		scfg.ClientAuth = NoClientCert
		scfg.Ext.PSK = &PSKConfig{Lookup: pskLookup([]byte("other")), TLS13: true}
		ccfg.Ext.PSK = &PSKConfig{Identity: testPSKIdentity, Key: testPSKKey, TLS13: true}
		c, _, err := xPair(t, ccfg, scfg)
		if err != nil || len(c.ConnectionState().PeerCertificates) == 0 || c.ConnectionState().Ext.PSKIdentity != nil {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("wrong key is a binder failure", func(t *testing.T) {
		ccfg, scfg := psk13(false, false)
		ccfg.Ext.PSK.Key = bytes.Repeat([]byte{7}, 32)
		if _, s, err := xPair(t, ccfg, scfg); err == nil || !strings.Contains(err.Error(), "decrypt") || s.ConnectionState().HandshakeComplete {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("no tickets, no resumption", func(t *testing.T) {
		ccfg, scfg := psk13(false, false)
		ccfg.ClientSessionCache = NewLRUClientSessionCache(4)
		for range 2 {
			c, s, err := xPair(t, ccfg, scfg)
			if err != nil {
				t.Fatal(err)
			}
			exchange(t, c, s)
			if c.ConnectionState().DidResume {
				t.Fatal("resumed")
			}
		}
	})
	t.Run("TLS 1.2 fallback with a TLS 1.3 PSK offer", func(t *testing.T) {
		ccfg, _ := psk13(false, false)
		ccfg.MinVersion = VersionTLS12
		ccfg.CipherSuites = []uint16{TLS_PSK_WITH_AES_128_GCM_SHA256}
		c, _, err := xPair(t, ccfg, pskServer(TLS_PSK_WITH_AES_128_GCM_SHA256))
		if err != nil || c.ConnectionState().Version != VersionTLS12 {
			t.Fatalf("err %v", err)
		}
	})
}

// rpkKey makes a P-256 key and its SPKI.
func rpkKey(t *testing.T) (crypto.Signer, []byte) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(k.Public())
	if err != nil {
		t.Fatal(err)
	}
	return k, spki
}

func pin(spkis ...[]byte) func([]byte) error {
	return func(got []byte) error {
		for _, s := range spkis {
			if bytes.Equal(s, got) {
				return nil
			}
		}
		return errors.New("key not pinned")
	}
}

// Raw public keys (RFC 7250) in TLS 1.2 and 1.3, both directions, checked
// against pinned keys, as TS-0003 v4.8.1 clause 10.2.3 requires of the
// certificate-based frameworks.
func TestRawPublicKeys(t *testing.T) {
	serverKey, serverSPKI := rpkKey(t)
	clientKey, clientSPKI := rpkKey(t)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	edSPKI, _ := x509.MarshalPKIXPublicKey(edPub)
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		name := map[uint16]string{VersionTLS12: "TLS 1.2", VersionTLS13: "TLS 1.3"}[v]
		t.Run(name+" mutual raw keys", func(t *testing.T) {
			scfg := &Config{MinVersion: v, MaxVersion: v, Certificates: []Certificate{RawPublicKeyCertificate(serverKey)},
				ClientAuth: RequireAnyClientCert, Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(clientSPKI), RawOnly: true}}}
			ccfg := &Config{MinVersion: v, MaxVersion: v, ServerName: "server.tlsx.test", Certificates: []Certificate{RawPublicKeyCertificate(clientKey)},
				Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(serverSPKI), RawOnly: true}}}
			c, s, err := xPair(t, ccfg, scfg)
			if err != nil {
				t.Fatal(err)
			}
			cs, ss := c.ConnectionState(), s.ConnectionState()
			if !bytes.Equal(cs.Ext.PeerRawPublicKey, serverSPKI) || !bytes.Equal(ss.Ext.PeerRawPublicKey, clientSPKI) ||
				len(cs.PeerCertificates) != 0 || !cs.Ext.OwnRawPublicKey || !ss.Ext.OwnRawPublicKey {
				t.Fatalf("client %+v server %+v", cs.Ext, ss.Ext)
			}
			exchange(t, c, s)
		})
		t.Run(name+" Ed25519 server key", func(t *testing.T) {
			scfg := &Config{MinVersion: v, MaxVersion: v, Certificates: []Certificate{RawPublicKeyCertificate(edPriv)},
				Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true}}}
			ccfg := &Config{MinVersion: v, MaxVersion: v, ServerName: "x", Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Verify: pin(edSPKI)}}}
			c, _, err := xPair(t, ccfg, scfg)
			if err != nil || !bytes.Equal(c.ConnectionState().Ext.PeerRawPublicKey, edSPKI) {
				t.Fatalf("err %v", err)
			}
		})
		t.Run(name+" key not pinned", func(t *testing.T) {
			scfg := &Config{MinVersion: v, MaxVersion: v, Certificates: []Certificate{RawPublicKeyCertificate(serverKey)},
				Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true}}}
			ccfg := &Config{MinVersion: v, MaxVersion: v, ServerName: "x", Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Verify: pin(clientSPKI)}}}
			if _, _, err := xPair(t, ccfg, scfg); err == nil || !strings.Contains(err.Error(), "not pinned") {
				t.Fatalf("err %v", err)
			}
		})
		t.Run(name+" client key not pinned", func(t *testing.T) {
			scfg := &Config{MinVersion: v, MaxVersion: v, Certificates: []Certificate{RawPublicKeyCertificate(serverKey)},
				ClientAuth: RequireAnyClientCert, Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(serverSPKI)}}}
			ccfg := &Config{MinVersion: v, MaxVersion: v, ServerName: "x", Certificates: []Certificate{RawPublicKeyCertificate(clientKey)},
				Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(serverSPKI)}}}
			if _, _, err := xPair(t, ccfg, scfg); err == nil {
				t.Fatal("unpinned client key accepted")
			}
		})
		t.Run(name+" X.509 server for a client accepting both", func(t *testing.T) {
			ccfg, scfg := xConfigs(t, testPKI(t).ecdsa)
			ccfg.MinVersion, ccfg.MaxVersion, scfg.MinVersion, scfg.MaxVersion = v, v, v, v
			ccfg.Ext.RawPublicKeys = &RawPublicKeyConfig{Verify: pin(serverSPKI)}
			c, _, err := xPair(t, ccfg, scfg)
			if err != nil || len(c.ConnectionState().VerifiedChains) == 0 {
				t.Fatalf("err %v", err)
			}
		})
		t.Run(name+" raw-only client refuses X.509", func(t *testing.T) {
			ccfg, scfg := xConfigs(t, testPKI(t).ecdsa)
			ccfg.MinVersion, ccfg.MaxVersion, scfg.MinVersion, scfg.MaxVersion = v, v, v, v
			ccfg.Ext.RawPublicKeys = &RawPublicKeyConfig{Verify: pin(serverSPKI), RawOnly: true}
			if _, _, err := xPair(t, ccfg, scfg); err == nil {
				t.Fatal("X.509 accepted")
			}
		})
		t.Run(name+" raw-only server and a client without RFC 7250", func(t *testing.T) {
			scfg := &Config{MinVersion: v, MaxVersion: v, Certificates: []Certificate{RawPublicKeyCertificate(serverKey)},
				Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true}}}
			ccfg := &Config{MinVersion: v, MaxVersion: v, ServerName: "x", InsecureSkipVerify: true}
			if _, _, err := xPair(t, ccfg, scfg); err == nil {
				t.Fatal("handshake without a usable certificate type")
			}
		})
		t.Run(name+" server with both sends X.509 to a plain client", func(t *testing.T) {
			ccfg, scfg := xConfigs(t, testPKI(t).ecdsa)
			ccfg.MinVersion, ccfg.MaxVersion, scfg.MinVersion, scfg.MaxVersion = v, v, v, v
			scfg.Ext.RawPublicKeys = &RawPublicKeyConfig{Send: true, Verify: pin(clientSPKI)}
			c, s, err := xPair(t, ccfg, scfg)
			if err != nil || len(c.ConnectionState().VerifiedChains) == 0 || len(s.ConnectionState().VerifiedChains) == 0 {
				t.Fatalf("err %v", err)
			}
		})
	}
}

// The legacy HMAC-SHA-1 CBC PSK suites (RFC 4279, RFC 5489) work from
// TLS 1.0, with encrypt_then_mac when negotiated; the TLS 1.2 PSK suites
// stay TLS 1.2 only. None is offered unless listed in CipherSuites.
func TestPSKLegacySuites(t *testing.T) {
	legacy := []uint16{TLS_PSK_WITH_AES_128_CBC_SHA, TLS_PSK_WITH_AES_256_CBC_SHA, TLS_DHE_PSK_WITH_AES_128_CBC_SHA,
		TLS_DHE_PSK_WITH_AES_256_CBC_SHA, TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA, TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA}
	for _, v := range []uint16{VersionTLS10, VersionTLS11, VersionTLS12} {
		for _, id := range legacy {
			for _, etm := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/etm=%v", VersionName(v), CipherSuiteName(id), etm), func(t *testing.T) {
					scfg, ccfg := pskServer(id), pskClient(id)
					scfg.MinVersion, scfg.MaxVersion, ccfg.MinVersion, ccfg.MaxVersion = v, v, v, v
					ccfg.CurvePreferences = []CurveID{X25519, FFDHE2048}
					scfg.CurvePreferences = []CurveID{X25519, FFDHE2048}
					ccfg.Ext.EncryptThenMAC, scfg.Ext.EncryptThenMAC = etm, etm
					c, s, err := xPair(t, ccfg, scfg)
					if err != nil {
						t.Fatal(err)
					}
					cs := c.ConnectionState()
					if cs.Version != v || cs.CipherSuite != id || cs.Ext.EncryptThenMAC != etm {
						t.Fatalf("%s %s etm %v", VersionName(cs.Version), CipherSuiteName(cs.CipherSuite), cs.Ext.EncryptThenMAC)
					}
					// TLS 1.0 CBC records are split 1/n-1: read it all.
					go c.Write([]byte("ping"))
					buf := make([]byte, 4)
					if _, err := io.ReadFull(s, buf); err != nil || string(buf) != "ping" {
						t.Fatalf("data: %q %v", buf, err)
					}
				})
			}
		}
	}
	t.Run("TLS 1.2 suites stay TLS 1.2 only", func(t *testing.T) {
		scfg, ccfg := pskServer(TLS_PSK_WITH_AES_128_CBC_SHA256), pskClient(TLS_PSK_WITH_AES_128_CBC_SHA256)
		scfg.MinVersion, scfg.MaxVersion, ccfg.MinVersion, ccfg.MaxVersion = VersionTLS11, VersionTLS11, VersionTLS11, VersionTLS11
		if _, _, err := xPair(t, ccfg, scfg); err == nil {
			t.Fatal("TLS_PSK_WITH_AES_128_CBC_SHA256 negotiated in TLS 1.1")
		}
	})
	t.Run("not offered unless listed", func(t *testing.T) {
		ccfg := pskClient()
		hello, _, _, err := (&Conn{config: ccfg, isClient: true}).makeClientHello()
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range legacy {
			if slices.Contains(hello.cipherSuites, id) {
				t.Errorf("%s offered by default", CipherSuiteName(id))
			}
		}
	})
}

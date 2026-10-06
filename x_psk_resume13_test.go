// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// clock is a settable Config.Time.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now().Truncate(time.Second)} } // whole seconds, as SessionState keeps them

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// resume13 is a TLS 1.3 external-PSK client and server with resumption,
// the server's keys in a table a test can change.
type resume13 struct {
	cc, sc         *Config
	keys           *pskKeys
	cclock, sclock *clock
}

func newResume13(allowNoDHE, preferNoDHE bool) *resume13 {
	r := &resume13{keys: &pskKeys{m: map[string][]byte{string(testPSKIdentity): testPSKKey}}, cclock: newClock(), sclock: newClock()}
	r.cc = &Config{ServerName: "server.tlsx.test", MinVersion: VersionTLS13, Time: r.cclock.now,
		ClientSessionCache: NewLRUClientSessionCache(4),
		Ext:                ConfigExt{PSK: &PSKConfig{Identity: testPSKIdentity, Key: testPSKKey, TLS13: true, Resumption: true, AllowNoDHE: allowNoDHE}}}
	r.sc = &Config{MinVersion: VersionTLS13, Time: r.sclock.now,
		Ext: ConfigExt{PSK: &PSKConfig{Lookup: r.keys.lookup, TLS13: true, Resumption: true, AllowNoDHE: allowNoDHE, PreferNoDHE: preferNoDHE}}}
	return r
}

// connect runs a handshake and data both ways, so the client reads the
// server's NewSessionTicket. It returns the client's state, and the
// ClientHellos the client sent.
func (r *resume13) connect(t *testing.T) (ConnectionState, []*clientHelloMsg, error) {
	t.Helper()
	cp, sp := localPipe(t)
	rec := &wireRecorder{Conn: cp}
	c, s := Client(rec, r.cc), Server(sp, r.sc)
	t.Cleanup(func() { c.Close(); s.Close() })
	errc := make(chan error, 1)
	go func() { errc <- s.Handshake() }()
	cerr := c.Handshake()
	serr := <-errc
	hellos := clientHellos(t, rec)
	if cerr != nil {
		return c.ConnectionState(), hellos, cerr
	}
	if serr != nil {
		return c.ConnectionState(), hellos, serr
	}
	cs, ss := c.ConnectionState(), s.ConnectionState()
	if cs.DidResume != ss.DidResume || !bytes.Equal(cs.Ext.PSKIdentity, ss.Ext.PSKIdentity) || cs.CurveID != ss.CurveID {
		t.Fatalf("client and server disagree: resumed %v/%v, identity %q/%q, group %v/%v",
			cs.DidResume, ss.DidResume, cs.Ext.PSKIdentity, ss.Ext.PSKIdentity, cs.CurveID, ss.CurveID)
	}
	if !bytes.Equal(cs.Ext.PSKIdentity, r.cc.Ext.PSK.Identity) || len(cs.PeerCertificates) != 0 {
		t.Fatalf("identity %q, %d certificates", cs.Ext.PSKIdentity, len(cs.PeerCertificates))
	}
	go func() { c.Write([]byte("ping")) }()
	buf := make([]byte, 4)
	if _, err := s.Read(buf); err != nil || string(buf) != "ping" {
		t.Fatalf("client to server: %q %v", buf, err)
	}
	go func() { s.Write([]byte("pong")) }()
	if _, err := c.Read(buf); err != nil || string(buf) != "pong" {
		t.Fatalf("server to client: %q %v", buf, err)
	}
	return cs, hellos, nil
}

// clientHellos parses the plaintext ClientHellos a client wrote.
func clientHellos(t *testing.T, rec *wireRecorder) []*clientHelloMsg {
	t.Helper()
	rec.mu.Lock()
	in := bytes.Clone(rec.out.Bytes())
	rec.mu.Unlock()
	var out []*clientHelloMsg
	for len(in) >= 5 {
		typ, n := in[0], int(in[3])<<8|int(in[4])
		if len(in) < 5+n {
			break
		}
		body := in[5 : 5+n]
		in = in[5+n:]
		if typ == byte(recordTypeApplicationData) {
			break
		}
		if typ != byte(recordTypeHandshake) || len(body) == 0 || body[0] != typeClientHello {
			continue
		}
		m := new(clientHelloMsg)
		if !m.unmarshal(body) {
			t.Fatal("ClientHello does not parse")
		}
		out = append(out, m)
	}
	return out
}

func (r *resume13) cached(t *testing.T) *SessionState {
	t.Helper()
	cs, ok := r.cc.ClientSessionCache.Get(r.cc.ServerName)
	if !ok || cs == nil {
		return nil
	}
	return cs.session
}

// TLS 1.3 resumption of external-PSK sessions (RFC 8446 2.2, 4.6.1), Go
// client and Go server.
func TestPSKResumptionTLS13(t *testing.T) {
	t.Run("psk_dhe_ke", func(t *testing.T) {
		r := newResume13(false, false)
		for i, want := range []bool{false, true, true} {
			cs, hellos, err := r.connect(t)
			if err != nil || cs.DidResume != want || cs.CurveID == 0 {
				t.Fatalf("connection %d: resumed %v, group %v, %v; want resumed %v with (EC)DHE", i, cs.DidResume, cs.CurveID, err, want)
			}
			if r.cached(t) == nil {
				t.Fatalf("connection %d: no ticket cached", i)
			}
			if len(hellos) != 1 || i > 0 && len(hellos[0].pskIdentities) != 2 {
				t.Fatalf("connection %d: %d ClientHellos", i, len(hellos))
			}
		}
	})
	t.Run("psk_ke", func(t *testing.T) {
		r := newResume13(true, true)
		for i, want := range []bool{false, true, true} {
			cs, hellos, err := r.connect(t)
			if err != nil || cs.DidResume != want || cs.CurveID != 0 {
				t.Fatalf("connection %d: resumed %v, group %v, %v; want resumed %v without (EC)DHE", i, cs.DidResume, cs.CurveID, err, want)
			}
			if modes := hellos[0].pskModes; !bytes.Equal(modes, []uint8{pskModeDHE, pskModePlain}) {
				t.Fatalf("connection %d: psk_key_exchange_modes %v", i, modes)
			}
		}
	})
	t.Run("psk_ke allowed, psk_dhe_ke used", func(t *testing.T) {
		r := newResume13(true, false)
		for i, want := range []bool{false, true} {
			if cs, _, err := r.connect(t); err != nil || cs.DidResume != want || cs.CurveID == 0 {
				t.Fatalf("connection %d: resumed %v, group %v, %v", i, cs.DidResume, cs.CurveID, err)
			}
		}
	})
	t.Run("psk_ke only on the server is not used for a client without it", func(t *testing.T) {
		r := newResume13(false, false)
		r.sc.Ext.PSK.AllowNoDHE, r.sc.Ext.PSK.PreferNoDHE = true, true
		for i, want := range []bool{false, true} {
			if cs, _, err := r.connect(t); err != nil || cs.DidResume != want || cs.CurveID == 0 {
				t.Fatalf("connection %d: resumed %v, group %v, %v", i, cs.DidResume, cs.CurveID, err)
			}
		}
	})
	t.Run("SHA-384", func(t *testing.T) {
		r := newResume13(false, false)
		r.cc.Ext.PSK.Hash, r.sc.Ext.PSK.Hash = crypto.SHA384, crypto.SHA384
		r.sc.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256}
		for i, want := range []bool{false, true} {
			cs, hellos, err := r.connect(t)
			if err != nil || cs.DidResume != want || cs.CipherSuite != TLS_AES_256_GCM_SHA384 {
				t.Fatalf("connection %d: resumed %v, suite %x, %v", i, cs.DidResume, cs.CipherSuite, err)
			}
			if want && (len(hellos[0].pskBinders) != 2 || len(hellos[0].pskBinders[1]) != 48) {
				t.Fatal("no SHA-384 binders")
			}
		}
	})

	t.Run("identities, ages and binders", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		ticket := r.cached(t)
		r.cclock.add(5 * time.Second)
		cs, hellos, err := r.connect(t)
		if err != nil || !cs.DidResume {
			t.Fatalf("resumed %v, %v", cs.DidResume, err)
		}
		ids := hellos[0].pskIdentities
		if len(ids) != 2 || !bytes.Equal(ids[0].label, ticket.ticket) || !bytes.Equal(ids[1].label, testPSKIdentity) {
			t.Fatalf("identities %+v: want the ticket, then the external identity", ids)
		}
		if want := uint32(5000) + ticket.ageAdd; ids[0].obfuscatedTicketAge != want {
			t.Errorf("ticket age %d, want %d", ids[0].obfuscatedTicketAge, want)
		}
		if ids[1].obfuscatedTicketAge != 0 {
			t.Errorf("external identity's age %d, want 0", ids[1].obfuscatedTicketAge)
		}
		if b := hellos[0].pskBinders; len(b) != 2 || bytes.Equal(b[0], b[1]) {
			t.Fatal("want two different binders")
		}
		if last := hellos[0].extensions[len(hellos[0].extensions)-1]; last != extensionPreSharedKey {
			t.Fatalf("last extension %d, want pre_shared_key", last)
		}
	})

	t.Run("server falls back to the external PSK", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		r.sc.SetSessionTicketKeys([][32]byte{{1, 2, 3}}) // the ticket no longer decrypts
		cs, hellos, err := r.connect(t)
		if err != nil || cs.DidResume || cs.HelloRetryRequest || len(hellos) != 1 || len(hellos[0].pskIdentities) != 2 {
			t.Fatalf("resumed %v, HRR %v, %v: want a full external-PSK handshake in one round trip", cs.DidResume, cs.HelloRetryRequest, err)
		}
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err) // the new ticket works
		}
	})

	t.Run("HelloRetryRequest", func(t *testing.T) {
		for _, fallback := range []bool{false, true} {
			r := newResume13(false, false)
			r.cc.CurvePreferences = []CurveID{X25519, CurveP256}
			r.sc.CurvePreferences = []CurveID{CurveP256}
			if _, _, err := r.connect(t); err != nil {
				t.Fatal(err)
			}
			ticket := r.cached(t)
			if fallback {
				r.sc.SetSessionTicketKeys([][32]byte{{4, 5, 6}})
			}
			r.cclock.add(2 * time.Second)
			cs, hellos, err := r.connect(t)
			if err != nil || cs.DidResume == fallback || !cs.HelloRetryRequest || len(hellos) != 2 {
				t.Fatalf("fallback %v: resumed %v, HRR %v, %d ClientHellos, %v", fallback, cs.DidResume, cs.HelloRetryRequest, len(hellos), err)
			}
			ids := hellos[1].pskIdentities
			if len(ids) != 2 || ids[0].obfuscatedTicketAge != 2000+ticket.ageAdd || ids[1].obfuscatedTicketAge != 0 {
				t.Fatalf("second ClientHello identities %+v", ids)
			}
			if bytes.Equal(hellos[0].pskBinders[1], hellos[1].pskBinders[1]) {
				t.Fatal("the external binder was not recomputed")
			}
		}
	})

	t.Run("ticket lifetime", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		r.sclock.add(maxSessionTicketLifetime + time.Hour) // the server refuses the old ticket
		cs, hellos, err := r.connect(t)
		if err != nil || cs.DidResume || len(hellos[0].pskIdentities) != 2 {
			t.Fatalf("resumed %v, %v", cs.DidResume, err)
		}
		r.cclock.add(maxSessionTicketLifetime + time.Hour) // the client drops its expired ticket
		r.sclock.add(maxSessionTicketLifetime + time.Hour)
		cs, hellos, err = r.connect(t)
		if err != nil || cs.DidResume || len(hellos[0].pskIdentities) != 1 || !bytes.Equal(hellos[0].pskIdentities[0].label, testPSKIdentity) {
			t.Fatalf("resumed %v, %v: want only the external identity offered", cs.DidResume, err)
		}
	})

	t.Run("off by default", func(t *testing.T) {
		for _, side := range []string{"both", "client", "server"} {
			r := newResume13(false, false)
			if side != "server" {
				r.cc.Ext.PSK.Resumption = false
			}
			if side != "client" {
				r.sc.Ext.PSK.Resumption = false
			}
			for i := range 2 {
				if cs, _, err := r.connect(t); err != nil || cs.DidResume {
					t.Fatalf("%s off, connection %d: resumed %v, %v", side, i, cs.DidResume, err)
				}
			}
			if r.cached(t) != nil {
				t.Fatalf("%s off: a session was cached", side)
			}
		}
	})

	t.Run("server refuses after the key is removed", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		r.keys.set(string(testPSKIdentity), nil)
		if cs, _, err := r.connect(t); err == nil || cs.DidResume {
			t.Fatalf("resumed %v, %v: want the handshake refused", cs.DidResume, err)
		}
		if r.cached(t) != nil {
			t.Fatal("the client kept the ticket of the failed resumption")
		}
	})

	t.Run("server refuses after the key is changed", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		r.keys.set(string(testPSKIdentity), bytes.Repeat([]byte{2}, 32)) // the client still has the old key
		cs, _, err := r.connect(t)
		if err == nil || cs.DidResume || !strings.Contains(err.Error(), "decrypt") {
			t.Fatalf("resumed %v, %v: want the external binder to fail", cs.DidResume, err)
		}
	})

	t.Run("server checks the binding of a ticket offered alone", func(t *testing.T) {
		// After the first connection the client's PSK hash changes, so its
		// external PSK no longer fits the session's suite and only the
		// ticket is offered. The server resumes it while the identity has
		// the session's key, and refuses it once the key changed.
		for _, changed := range []bool{false, true} {
			r := newResume13(false, false)
			if _, _, err := r.connect(t); err != nil {
				t.Fatal(err)
			}
			r.cc.Ext.PSK.Hash = crypto.SHA384
			if changed {
				r.keys.set(string(testPSKIdentity), bytes.Repeat([]byte{2}, 32))
			}
			cs, hellos, err := r.connect(t)
			if len(hellos) != 1 || len(hellos[0].pskIdentities) != 1 || bytes.Equal(hellos[0].pskIdentities[0].label, testPSKIdentity) {
				t.Fatalf("key changed %v: want only the ticket offered", changed)
			}
			if changed && (err == nil || cs.DidResume) || !changed && (err != nil || !cs.DidResume) {
				t.Fatalf("key changed %v: resumed %v, %v", changed, cs.DidResume, err)
			}
		}
	})

	t.Run("client drops a session of a changed key", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		key2 := bytes.Repeat([]byte{2}, 32)
		r.keys.set(string(testPSKIdentity), key2)
		r.cc.Ext.PSK.Key = key2
		cs, hellos, err := r.connect(t)
		if err != nil || cs.DidResume || len(hellos[0].pskIdentities) != 1 || !bytes.Equal(hellos[0].pskIdentities[0].label, testPSKIdentity) {
			t.Fatalf("resumed %v, %v: want a full handshake with the new key", cs.DidResume, err)
		}
		if cs, _, err := r.connect(t); err != nil || !cs.DidResume {
			t.Fatalf("resumed %v, %v: want the new key's session resumed", cs.DidResume, err)
		}
	})

	t.Run("client does not offer a session of another identity", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		r.cc.Ext.PSK.Identity = []byte("dev-2")
		r.keys.set("dev-2", testPSKKey)
		cs, hellos, err := r.connect(t)
		if err != nil || cs.DidResume || len(hellos[0].pskIdentities) != 1 || string(cs.Ext.PSKIdentity) != "dev-2" {
			t.Fatalf("resumed %v, %v: want a full handshake as dev-2", cs.DidResume, err)
		}
	})

	t.Run("server without tickets uses the external PSK", func(t *testing.T) {
		r := newResume13(false, false)
		if _, _, err := r.connect(t); err != nil {
			t.Fatal(err)
		}
		r.sc.SessionTicketsDisabled = true
		if cs, _, err := r.connect(t); err != nil || cs.DidResume {
			t.Fatalf("resumed %v, %v", cs.DidResume, err)
		}
	})
}

// A session of an external PSK is resumed in the inner ClientHello of
// Encrypted Client Hello like any ticket; the external identity is not
// offered with it, and never appears on the wire.
func TestPSKResumptionTLS13ECH(t *testing.T) {
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

	r := newResume13(false, false)
	r.cc.ServerName = "secret.example"
	r.sc.Certificates = []Certificate{{Certificate: [][]byte{publicDER}, PrivateKey: k}}
	r.sc.EncryptedClientHelloKeys = []EncryptedClientHelloKey{{Config: echConfig, PrivateKey: echKey.Bytes()}}
	if cs, _, err := r.connect(t); err != nil || cs.DidResume || cs.ECHAccepted {
		t.Fatalf("first connection: resumed %v, ECH %v, %v", cs.DidResume, cs.ECHAccepted, err)
	}

	r.cc.EncryptedClientHelloConfigList = list.BytesOrPanic()
	cp, sp := localPipe(t)
	rec := &wireRecorder{Conn: cp}
	c, s := Client(rec, r.cc), Server(sp, r.sc)
	t.Cleanup(func() { c.Close(); s.Close() })
	errc := make(chan error, 1)
	go func() { errc <- s.Handshake() }()
	if err := c.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	cs, ss := c.ConnectionState(), s.ConnectionState()
	if !cs.ECHAccepted || !cs.DidResume || !ss.DidResume || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) || !bytes.Equal(ss.Ext.PSKIdentity, testPSKIdentity) {
		t.Fatalf("ECH %v, resumed %v/%v, identity %q/%q", cs.ECHAccepted, cs.DidResume, ss.DidResume, cs.Ext.PSKIdentity, ss.Ext.PSKIdentity)
	}
	hellos := clientHellos(t, rec)
	if len(hellos) != 1 || len(hellos[0].pskIdentities) != 0 {
		t.Fatal("the outer ClientHello carries a PSK")
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if bytes.Contains(rec.out.Bytes(), testPSKIdentity) {
		t.Fatal("the client sent the external PSK identity in clear")
	}
}

// A client that offers psk_ke only (tlsx's client always offers psk_dhe_ke
// too): a server resumes a session bound to an external PSK only with
// AllowNoDHE, never a certificate session, and then answers without a key
// share and sends tickets.
func TestPSKResumptionTLS13PSKKEOnly(t *testing.T) {
	keys := &pskKeys{m: map[string][]byte{string(testPSKIdentity): testPSKKey}}
	b := &pskBinding{identity: testPSKIdentity, fingerprint: pskFingerprint(testPSKKey)}
	bound := &SessionState{version: VersionTLS13, Extra: [][]byte{b.marshal()}}
	unbound := &SessionState{version: VersionTLS13}
	for _, allow := range []bool{false, true} {
		c := &Conn{config: &Config{Ext: ConfigExt{PSK: &PSKConfig{Lookup: keys.lookup, TLS13: true, Resumption: true, AllowNoDHE: allow}}}}
		hs := &serverHandshakeStateTLS13{c: c, ctx: context.Background(),
			clientHello: &clientHelloMsg{pskModes: []uint8{pskModePlain}},
			hello:       &serverHelloMsg{serverShare: keyShare{group: X25519, data: []byte{1}}}, sharedKey: []byte{1}}
		if hs.pskPlainResumptionOK() != allow || hs.checkPSKSession13X(bound) != allow || hs.checkPSKSession13X(unbound) {
			t.Fatalf("AllowNoDHE %v: wrong resumption decision", allow)
		}
		if !allow {
			continue
		}
		hs.resumedPSKSession13X(bound)
		if hs.sharedKey != nil || hs.hello.serverShare.group != 0 || !bytes.Equal(c.x.pskIdentity, testPSKIdentity) {
			t.Fatal("psk_ke resumption kept a key share")
		}
		if !hs.shouldSendSessionTickets() {
			t.Fatal("no tickets for a psk_ke session")
		}
	}
}

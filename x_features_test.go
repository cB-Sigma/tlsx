// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Go-to-Go tests of the features tlsx adds. The same features are run
// against OpenSSL in x_openssl_test.go.

// echo serves c until it fails: every read is written back.
func echo(c *Conn) {
	buf := make([]byte, 32<<10)
	for {
		n, err := c.Read(buf)
		if n > 0 {
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// roundTrip writes msg and reads it back from an echoing peer.
func roundTrip(t *testing.T, c *Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != msg {
		t.Fatalf("echo %q, want %q", got, msg)
	}
}

type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func (l *eventLog) add(_ *Conn, e Event) {
	l.mu.Lock()
	l.ev = append(l.ev, e)
	l.mu.Unlock()
}

func (l *eventLog) count(k EventKind) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.ev {
		if e.Kind == k {
			n++
		}
	}
	return n
}

func (l *eventLog) last(k EventKind) (Event, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := len(l.ev) - 1; i >= 0; i-- {
		if l.ev[i].Kind == k {
			return l.ev[i], true
		}
	}
	return Event{}, false
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestDefaultsUnchanged: with a zero Config.Ext and the default suites and
// groups, tlsx sends what crypto/tls sends (no tlsx extension, suite or
// group) and negotiates what it negotiates; the upstream test suite
// (recorded handshakes against OpenSSL included) runs on the copy.
func TestDefaultsUnchanged(t *testing.T) {
	c := &Conn{config: &Config{ServerName: "example"}, isClient: true}
	hello, _, _, err := c.makeClientHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.x.encryptThenMAC || hello.x.maxFragmentLength != 0 || hello.x.statusRequestV2 || hello.x.hasTrustedCAKeys ||
		len(hello.x.certificateAuthorities) != 0 {
		t.Fatalf("tlsx extensions in a default ClientHello: %+v", hello.x)
	}
	for _, id := range hello.cipherSuites {
		if isTLSXSuite(id) {
			t.Fatalf("default ClientHello offers %s", CipherSuiteName(id))
		}
	}
	for _, g := range hello.supportedCurves {
		if slices.Contains(tlsxGroups, g) {
			t.Fatalf("default ClientHello offers group %v", g)
		}
	}
	for _, s := range hello.supportedSignatureAlgorithms {
		if _, _, ok := typeAndHashX(s); ok {
			t.Fatalf("default ClientHello offers %v", s)
		}
	}
	cc, sc := xConfigs(t, testPKI(t).ecdsa)
	cc.Certificates, sc.ClientAuth = nil, NoClientCert
	client, _, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if s := client.ConnectionState(); s.Version != VersionTLS13 || s.CipherSuite == TLS_AES_128_CCM_SHA256 || s.Ext.Handshakes != 1 {
		t.Fatalf("%+v", s)
	}
}

func TestKeyUpdateBothDirections(t *testing.T) {
	cc, sc := xConfigs(t, testPKI(t).rsa)
	cc.MinVersion, sc.MinVersion = VersionTLS13, VersionTLS13
	var clog, slog eventLog
	cc.Ext.Observer, sc.Ext.Observer = clog.add, slog.add
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	go echo(server)
	roundTrip(t, client, "before")

	// Client updates and asks the server to update too (RFC 8446 4.6.3).
	if err := client.SendKeyUpdate(true); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, client, "after client update")
	cs, ss := client.ConnectionState().Ext, server.ConnectionState().Ext
	if cs.KeyUpdatesSent != 1 || cs.KeyUpdatesReceived != 1 || ss.KeyUpdatesReceived != 1 || ss.KeyUpdatesSent != 1 {
		t.Fatalf("client sent %d received %d, server sent %d received %d", cs.KeyUpdatesSent, cs.KeyUpdatesReceived, ss.KeyUpdatesSent, ss.KeyUpdatesReceived)
	}
	if e, _ := slog.last(EventKeyUpdateReceived); !e.Requested {
		t.Fatal("server did not see update_requested")
	}
	if e, _ := slog.last(EventKeyUpdateSent); e.Requested {
		t.Fatal("server's answer must be update_not_requested")
	}

	// Server updates without a request: only its sending keys change.
	if err := server.SendKeyUpdate(false); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, client, "after server update")
	if n := client.ConnectionState().Ext.KeyUpdatesReceived; n != 2 {
		t.Fatalf("client received %d updates, want 2", n)
	}
	if n := client.ConnectionState().Ext.KeyUpdatesSent; n != 1 {
		t.Fatalf("client answered an unrequested update (%d sent)", n)
	}
	if clog.count(EventKeyUpdateReceived) != 2 || slog.count(EventKeyUpdateSent) != 2 {
		t.Fatal("observer events missing")
	}

	// Many updates while data flows.
	for i := 0; i < 20; i++ {
		if err := client.SendKeyUpdate(i%2 == 0); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, client, "loop")
	}

	// TLS 1.2 has no KeyUpdate.
	cc2, sc2 := xConfigs(t, testPKI(t).rsa)
	cc2.MaxVersion = VersionTLS12
	c2, _, err := xPair(t, cc2, sc2)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.SendKeyUpdate(true); !errors.Is(err, ErrNotTLS13) {
		t.Fatalf("TLS 1.2 SendKeyUpdate: %v", err)
	}
}

func renegConfigs(t *testing.T) (cc, sc *Config, clog, slog *eventLog, cver, sver *atomic.Int32) {
	cc, sc = xConfigs(t, testPKI(t).rsa)
	cc.MaxVersion, sc.MaxVersion = VersionTLS12, VersionTLS12
	cc.Renegotiation = RenegotiateFreelyAsClient
	sc.Ext.AcceptRenegotiation = true
	clog, slog = &eventLog{}, &eventLog{}
	cc.Ext.Observer, sc.Ext.Observer = clog.add, slog.add
	cver, sver = &atomic.Int32{}, &atomic.Int32{}
	cc.VerifyConnection = func(cs ConnectionState) error { cver.Add(1); return nil }
	sc.VerifyConnection = func(cs ConnectionState) error { sver.Add(1); return nil }
	return
}

func TestRenegotiationClientInitiated(t *testing.T) {
	cc, sc, clog, slog, cver, sver := renegConfigs(t)
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	go echo(server)
	if !client.ConnectionState().Ext.SecureRenegotiation {
		t.Fatal("RFC 5746 not negotiated")
	}
	roundTrip(t, client, "one")

	// A reader blocked in Read hands the connection to the renegotiation.
	readDone := make(chan string, 1)
	go func() {
		b := make([]byte, 5)
		_, err := io.ReadFull(client, b)
		if err != nil {
			readDone <- err.Error()
			return
		}
		readDone <- string(b)
	}()
	time.Sleep(50 * time.Millisecond)
	if err := client.Renegotiate(); err != nil {
		t.Fatalf("Renegotiate: %v", err)
	}
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := <-readDone; got != "hello" {
		t.Fatalf("blocked reader got %q", got)
	}
	cs := client.ConnectionState()
	if cs.Ext.Handshakes != 2 || cs.DidResume {
		t.Fatalf("handshakes %d resumed %v", cs.Ext.Handshakes, cs.DidResume)
	}
	// Full re-validation of both certificates (IEC 62351-3 7.4.5).
	if cver.Load() != 2 || sver.Load() != 2 {
		t.Fatalf("VerifyConnection ran %d times on the client, %d on the server; want 2 each", cver.Load(), sver.Load())
	}
	waitFor(t, "server renegotiated event", func() bool { return slog.count(EventRenegotiated) == 1 })
	if e, _ := slog.last(EventRenegotiated); !e.ByPeer {
		t.Fatal("server event does not say the peer started it")
	}
	if clog.count(EventRenegotiated) != 1 {
		t.Fatal("client event missing")
	}
	roundTrip(t, client, "two")

	// Data flowing both ways while renegotiating.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			roundTrip(t, client, "concurrent")
		}
	}()
	for i := 0; i < 3; i++ {
		if err := client.Renegotiate(); err != nil {
			t.Fatalf("renegotiation %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
	if n := client.ConnectionState().Ext.Handshakes; n != 5 {
		t.Fatalf("%d handshakes", n)
	}
}

func TestRenegotiationResume(t *testing.T) {
	cc, sc, _, _, cver, _ := renegConfigs(t)
	cc.ClientSessionCache = NewLRUClientSessionCache(4)
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	go echo(server)
	roundTrip(t, client, "x")
	before := client.ConnectionState()
	if err := client.Resume(); err != nil {
		t.Fatal(err)
	}
	after := client.ConnectionState()
	if !after.DidResume || after.Ext.Handshakes != 2 {
		t.Fatalf("resumed %v handshakes %d", after.DidResume, after.Ext.Handshakes)
	}
	if bytes.Equal(before.TLSUnique, after.TLSUnique) {
		t.Fatal("keys (tls-unique) did not change")
	}
	// A resumed renegotiation still runs VerifyConnection (revocation and
	// expiry checks of the profile) without a certificate exchange.
	if cver.Load() != 2 {
		t.Fatalf("VerifyConnection ran %d times", cver.Load())
	}
	roundTrip(t, client, "y")
	if err := client.Renegotiate(); err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().DidResume {
		t.Fatal("Renegotiate resumed")
	}
}

func TestRenegotiationServerInitiated(t *testing.T) {
	cc, sc, clog, slog, cver, sver := renegConfigs(t)
	sc.Ext.AcceptRenegotiation = false // a requested renegotiation is still answered
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	go echo(client) // the client must be reading to see HelloRequest
	if err := server.RequestRenegotiation(); err != nil {
		t.Fatal(err)
	}
	// The server processes the client's ClientHello as it reads.
	if _, err := server.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 4)
	server.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(server, b); err != nil || string(b) != "ping" {
		t.Fatalf("read %q %v", b, err)
	}
	waitFor(t, "renegotiation", func() bool { return slog.count(EventRenegotiated) == 1 })
	if server.ConnectionState().Ext.Handshakes != 2 {
		t.Fatal("server handshake count")
	}
	if e, _ := slog.last(EventRenegotiated); e.ByPeer {
		t.Fatal("server-requested renegotiation reported as the peer's")
	}
	if slog.count(EventHelloRequestSent) != 1 || clog.count(EventRenegotiated) != 1 {
		t.Fatal("events")
	}
	if cver.Load() != 2 || sver.Load() != 2 {
		t.Fatalf("VerifyConnection ran %d and %d times", cver.Load(), sver.Load())
	}
	if err := client.RequestRenegotiation(); err == nil {
		t.Fatal("a client cannot send HelloRequest")
	}
}

func TestRenegotiationRefusals(t *testing.T) {
	t.Run("server does not accept", func(t *testing.T) {
		cc, sc, clog, slog, _, _ := renegConfigs(t)
		sc.Ext.AcceptRenegotiation = false
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		go echo(server)
		if err := client.Renegotiate(); !errors.Is(err, ErrRenegotiationRefusedByPeer) {
			t.Fatalf("got %v", err)
		}
		roundTrip(t, client, "still usable")
		if e, ok := slog.last(EventRenegotiationRefused); !ok || !errors.Is(e.Err, ErrRenegotiationNotAllowed) {
			t.Fatal("server event")
		}
		if clog.count(EventRenegotiationRefused) != 1 {
			t.Fatal("client event")
		}
	})
	t.Run("client does not renegotiate", func(t *testing.T) {
		cc, sc, _, _, _, _ := renegConfigs(t)
		cc.Renegotiation = RenegotiateNever
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Renegotiate(); !errors.Is(err, ErrRenegotiationNotAllowed) {
			t.Fatalf("got %v", err)
		}
		go echo(client)
		if err := server.RequestRenegotiation(); err != nil {
			t.Fatal(err)
		}
		server.Write([]byte("x"))
		server.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 1)
		// The client answers no_renegotiation (a warning) and fails its read.
		io.ReadFull(server, b)
		if server.ConnectionState().Ext.Handshakes != 1 {
			t.Fatal("renegotiated")
		}
	})
	t.Run("insecure peer", func(t *testing.T) {
		cc, sc, _, slog, _, _ := renegConfigs(t)
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		// Pretend the client never signalled RFC 5746 (every Go and
		// OpenSSL peer does): the server must abort a renegotiation.
		server.x.peerSecureReneg = false
		srvErr := make(chan error, 1)
		go func() {
			b := make([]byte, 1)
			_, err := server.Read(b)
			srvErr <- err
		}()
		if err := client.Renegotiate(); err == nil {
			t.Fatal("renegotiation with an insecure peer succeeded")
		}
		if err := <-srvErr; !errors.Is(err, ErrInsecureRenegotiation) {
			t.Fatalf("server: %v", err)
		}
		if e, ok := slog.last(EventRenegotiationRefused); !ok || !errors.Is(e.Err, ErrInsecureRenegotiation) {
			t.Fatal("event")
		}
		if err := server.RequestRenegotiation(); !errors.Is(err, ErrInsecureRenegotiation) {
			t.Fatalf("RequestRenegotiation: %v", err)
		}
		c2, _, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		c2.secureRenegotiation = false
		if err := c2.Renegotiate(); !errors.Is(err, ErrInsecureRenegotiation) {
			t.Fatalf("client: %v", err)
		}
	})
	t.Run("identity change", func(t *testing.T) {
		cc, sc, _, _, _, _ := renegConfigs(t)
		var n atomic.Int32
		p := testPKI(t)
		sc.Certificates = nil
		sc.GetCertificate = func(*ClientHelloInfo) (*Certificate, error) {
			if n.Add(1) == 1 {
				return &p.rsa.cert, nil
			}
			return &p.ecdsa.cert, nil
		}
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		go echo(server)
		if err := client.Renegotiate(); err == nil || !bytes.Contains([]byte(err.Error()), []byte("identity changed")) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("certificate re-validation fails", func(t *testing.T) {
		cc, sc, clog, _, _, _ := renegConfigs(t)
		var n atomic.Int32
		cc.VerifyConnection = func(cs ConnectionState) error {
			if n.Add(1) > 1 {
				return errors.New("revoked since")
			}
			return nil
		}
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		go echo(server)
		if err := client.Renegotiate(); err == nil {
			t.Fatal("renegotiation passed a failing certificate check")
		}
		if _, err := client.Write([]byte("x")); err == nil {
			t.Fatal("connection usable after a failed renegotiation")
		}
		if clog.count(EventRenegotiationFailed) != 1 {
			t.Fatal("event")
		}
	})
	t.Run("TLS 1.3", func(t *testing.T) {
		cc, sc := xConfigs(t, testPKI(t).rsa)
		cc.Renegotiation = RenegotiateFreelyAsClient
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Renegotiate(); !errors.Is(err, ErrNotTLS12) {
			t.Fatal(err)
		}
		if err := server.RequestRenegotiation(); !errors.Is(err, ErrNotTLS12) {
			t.Fatal(err)
		}
	})
}

func TestRenegotiationVersionChange(t *testing.T) {
	c := &Conn{handshakes: 1, conn: nopConn{}, config: &Config{}}
	err := c.checkRenegotiationVersion(VersionTLS12, VersionTLS13)
	if !errors.Is(err, ErrRenegotiationVersionChange) {
		t.Fatalf("got %v", err)
	}
	if c.vers != VersionTLS12 {
		t.Fatal("version not kept")
	}
	if err := (&Conn{}).checkRenegotiationVersion(0, VersionTLS13); err != nil {
		t.Fatal("first handshake refused")
	}
	// A client renegotiation offers only the connection's version.
	c = &Conn{handshakes: 1, vers: VersionTLS12}
	if v := c.renegotiationVersions([]uint16{VersionTLS13, VersionTLS12}); !slices.Equal(v, []uint16{VersionTLS12}) {
		t.Fatalf("offered %v", v)
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Write(b []byte) (int, error) { return len(b), nil }

func TestDHESuites(t *testing.T) {
	for _, tc := range []struct {
		suite  uint16
		groups []CurveID
		want   CurveID
	}{
		{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, []CurveID{FFDHE2048}, FFDHE2048},
		{TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, []CurveID{FFDHE3072, FFDHE2048}, FFDHE3072},
		{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, []CurveID{FFDHE4096}, FFDHE4096},
	} {
		cc, sc := xConfigs(t, testPKI(t).rsa)
		cc.MaxVersion = VersionTLS12
		cc.CipherSuites, sc.CipherSuites = []uint16{tc.suite}, []uint16{tc.suite}
		cc.CurvePreferences, sc.CurvePreferences = tc.groups, tc.groups
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatalf("%s: %v", CipherSuiteName(tc.suite), err)
		}
		cs := client.ConnectionState()
		if cs.CipherSuite != tc.suite || cs.CurveID != tc.want {
			t.Fatalf("suite %s group %v", CipherSuiteName(cs.CipherSuite), cs.CurveID)
		}
		go echo(server)
		roundTrip(t, client, "dhe")
	}
	// No common finite field group: no DHE suite.
	cc, sc := xConfigs(t, testPKI(t).rsa)
	cc.MaxVersion = VersionTLS12
	cc.CipherSuites, sc.CipherSuites = []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}, []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}
	cc.CurvePreferences, sc.CurvePreferences = []CurveID{FFDHE3072, CurveP256}, []CurveID{FFDHE2048, CurveP256}
	if _, _, err := xPair(t, cc, sc); err == nil {
		t.Fatal("handshake without a common group")
	}
}

func TestFFDHEGroupsRFC7919(t *testing.T) {
	// The primes are safe primes, 2 generates the prime-order subgroup,
	// and ffdhe2048 is 2^2048 - 2^1984 + (floor(2^1918 * e) + 560316) *
	// 2^64 - 1 (RFC 7919 A.1), e summed to 4000 bits.
	for id, g := range ffdheGroups {
		p := new(big.Int).SetBytes(g.pBytes)
		q := new(big.Int).Rsh(p, 1)
		if !p.ProbablyPrime(20) || !q.ProbablyPrime(20) {
			t.Fatalf("%v: p or (p-1)/2 not prime", id)
		}
		if new(big.Int).Exp(big.NewInt(2), q, p).Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("%v: 2 does not generate the order-q subgroup", id)
		}
		if p.BitLen() != map[CurveID]int{FFDHE2048: 2048, FFDHE3072: 3072, FFDHE4096: 4096}[id] {
			t.Fatalf("%v: %d bits", id, p.BitLen())
		}
	}
	e := new(big.Float).SetPrec(4000)
	term := new(big.Float).SetPrec(4000).SetInt64(1)
	for k := int64(1); k < 400; k++ { // e = sum of 1/k!
		e.Add(e, term)
		term.Quo(term, new(big.Float).SetPrec(4000).SetInt64(k))
	}
	f := new(big.Float).SetPrec(4000).Mul(new(big.Float).SetPrec(4000).SetMantExp(big.NewFloat(1), 1918), e)
	fi, _ := f.Int(nil)
	want := new(big.Int).Lsh(big.NewInt(1), 2048)
	want.Sub(want, new(big.Int).Lsh(big.NewInt(1), 1984))
	want.Add(want, new(big.Int).Lsh(new(big.Int).Add(fi, big.NewInt(560316)), 64))
	want.Sub(want, big.NewInt(1))
	if want.Cmp(new(big.Int).SetBytes(ffdheGroups[FFDHE2048].pBytes)) != 0 {
		t.Fatal("ffdhe2048 does not match the RFC 7919 formula")
	}
	// Only the RFC 7919 groups are accepted from a server.
	g := ffdheGroups[FFDHE2048]
	if ffdheGroupByParams(g.pBytes, []byte{2}) != g || ffdheGroupByParams(append([]byte{0}, g.pBytes...), []byte{0, 2}) != g {
		t.Fatal("ffdhe2048 not recognised")
	}
	small := make([]byte, 128)
	small[0], small[127] = 0xff, 0x61
	if ffdheGroupByParams(small, []byte{2}) != nil || ffdheGroupByParams(g.pBytes, []byte{5}) != nil {
		t.Fatal("custom group accepted")
	}
	// Public values out of range are refused.
	priv, _, err := g.generate(zeroReaderX{})
	if err == nil {
		pm1 := new(big.Int).Sub(new(big.Int).SetBytes(g.pBytes), big.NewInt(1)).Bytes()
		for _, y := range [][]byte{{0}, {1}, pm1, g.pBytes} {
			if _, err := g.shared(priv, y); err == nil {
				t.Fatalf("public value %x accepted", y[:min(4, len(y))])
			}
		}
	}
}

type zeroReaderX struct{}

func (zeroReaderX) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 7
	}
	return len(b), nil
}

func TestFFDHEAndBrainpoolTLS13Groups(t *testing.T) {
	for _, g := range []CurveID{FFDHE2048, FFDHE3072, BrainpoolP256r1TLS13, BrainpoolP384r1TLS13} {
		cc, sc := xConfigs(t, testPKI(t).rsa)
		cc.MinVersion = VersionTLS13
		cc.CurvePreferences, sc.CurvePreferences = []CurveID{g}, []CurveID{CurveP256, g}
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatalf("%v: %v", g, err)
		}
		if cs := client.ConnectionState(); cs.CurveID != g || cs.Version != VersionTLS13 {
			t.Fatalf("group %v version %x", cs.CurveID, cs.Version)
		}
		go echo(server)
		roundTrip(t, client, "group")
	}
	// HelloRetryRequest to ffdhe2048.
	cc, sc := xConfigs(t, testPKI(t).rsa)
	cc.MinVersion = VersionTLS13
	cc.CurvePreferences, sc.CurvePreferences = []CurveID{CurveP384, FFDHE2048}, []CurveID{FFDHE2048}
	client, _, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if cs := client.ConnectionState(); cs.CurveID != FFDHE2048 || !cs.HelloRetryRequest {
		t.Fatalf("group %v HRR %v", cs.CurveID, cs.HelloRetryRequest)
	}
}

func TestAES128CCMSHA256(t *testing.T) {
	cc, sc := xConfigs(t, testPKI(t).ecdsa)
	cc.MinVersion = VersionTLS13
	cc.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_128_CCM_SHA256}
	sc.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_128_CCM_SHA256, TLS_AES_128_GCM_SHA256}
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if cs := client.ConnectionState(); cs.CipherSuite != TLS_AES_128_CCM_SHA256 {
		t.Fatalf("suite %s", CipherSuiteName(cs.CipherSuite))
	}
	go echo(server)
	roundTrip(t, client, string(bytes.Repeat([]byte("ccm"), 10000)))
	if err := client.SendKeyUpdate(true); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, client, "after update")
	// Not offered by default.
	cc2, sc2 := xConfigs(t, testPKI(t).ecdsa)
	sc2.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_128_CCM_SHA256}
	if _, _, err := xPair(t, cc2, sc2); err == nil {
		t.Fatal("CCM negotiated with a client that does not offer it")
	}
}

func TestEncryptThenMAC(t *testing.T) {
	for _, tc := range []struct {
		suite uint16
		leaf  func(*xPKI) xLeaf
	}{
		{TLS_RSA_WITH_AES_128_CBC_SHA256, func(p *xPKI) xLeaf { return p.rsa }},
		{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, func(p *xPKI) xLeaf { return p.rsa }},
		{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, func(p *xPKI) xLeaf { return p.ecdsa }},
		{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, func(p *xPKI) xLeaf { return p.rsa }},
	} {
		cc, sc := xConfigs(t, tc.leaf(testPKI(t)))
		cc.MaxVersion = VersionTLS12
		cc.CipherSuites, sc.CipherSuites = []uint16{tc.suite}, []uint16{tc.suite}
		cc.Ext.EncryptThenMAC, sc.Ext.RequireEncryptThenMAC = true, true
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatalf("%s: %v", CipherSuiteName(tc.suite), err)
		}
		if cs, ss := client.ConnectionState(), server.ConnectionState(); !cs.Ext.EncryptThenMAC || !ss.Ext.EncryptThenMAC || cs.CipherSuite != tc.suite {
			t.Fatalf("%s: encrypt_then_mac not in use", CipherSuiteName(tc.suite))
		}
		go echo(server)
		for _, n := range []int{0, 1, 15, 16, 17, 1000, 16384} {
			roundTrip(t, client, string(bytes.Repeat([]byte{'e'}, n))+"!")
		}
	}
	// Required but not offered: refused by the server (IEC 62351-3 7.5.7).
	cc, sc := xConfigs(t, testPKI(t).rsa)
	cc.MaxVersion = VersionTLS12
	cc.CipherSuites, sc.CipherSuites = []uint16{TLS_RSA_WITH_AES_128_CBC_SHA256}, []uint16{TLS_RSA_WITH_AES_128_CBC_SHA256}
	sc.Ext.RequireEncryptThenMAC = true
	if _, _, err := xPair(t, cc, sc); err == nil {
		t.Fatal("CBC without encrypt_then_mac accepted")
	}
	// Required by the client, server does not do it: the client aborts.
	cc.Ext.RequireEncryptThenMAC, sc.Ext.RequireEncryptThenMAC = true, false
	if _, _, err := xPair(t, cc, sc); err == nil {
		t.Fatal("client accepted CBC without encrypt_then_mac")
	}
	// Without the setting on either side, plain MAC-then-encrypt as upstream.
	cc.Ext.RequireEncryptThenMAC = false
	client, _, err := xPair(t, cc, sc)
	if err != nil || client.ConnectionState().Ext.EncryptThenMAC {
		t.Fatalf("%v", err)
	}
}

func TestEncryptThenMACRecordLayer(t *testing.T) {
	// A changed ciphertext or MAC byte is bad_record_mac, checked before
	// decryption.
	key := bytes.Repeat([]byte{1}, 16)
	macKey := bytes.Repeat([]byte{2}, 32)
	mk := func() *halfConn {
		return &halfConn{version: VersionTLS12, cipher: cipherAES(key, make([]byte, 16), false).(cbcMode),
			mac: macSHA256(macKey), etm: true}
	}
	w, r := mk(), mk()
	r.cipher = cipherAES(key, make([]byte, 16), true)
	rec := []byte{byte(recordTypeApplicationData), 3, 3, 0, 0}
	rec, err := w.encrypt(rec, []byte("encrypt then mac"), zeroReaderX{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec) != 5+16+32+32 { // IV, two blocks, MAC
		t.Fatalf("record %d bytes", len(rec))
	}
	for i := 5; i < len(rec); i += 7 {
		bad := slices.Clone(rec)
		bad[i] ^= 0x80
		rr := mk()
		rr.cipher = cipherAES(key, make([]byte, 16), true)
		if _, _, err := rr.decrypt(bad); err != alertBadRecordMAC {
			t.Fatalf("byte %d changed: %v", i, err)
		}
	}
	plain, typ, err := r.decrypt(slices.Clone(rec))
	if err != nil || typ != recordTypeApplicationData || string(plain) != "encrypt then mac" {
		t.Fatalf("%q %v", plain, err)
	}
}

func TestRSAPSSPSS(t *testing.T) {
	p := testPKI(t)
	if !IsRSAPSSKey(p.pss.x509) {
		t.Fatal("test certificate does not have a PSS key")
	}
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		cc, sc := xConfigs(t, p.pss)
		cc.MaxVersion = v
		schemes := []SignatureScheme{PSSPSSWithSHA256, PSSPSSWithSHA384, PSSWithSHA256, ECDSAWithP256AndSHA256, PKCS1WithSHA256}
		cc.Ext.SignatureSchemes, sc.Ext.SignatureSchemes = schemes, schemes
		cc.Certificates = []Certificate{p.pss.cert} // PSS client certificate too
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatalf("%s: %v", VersionName(v), err)
		}
		if got := client.ConnectionState().testingOnlyPeerSignatureAlgorithm; got != PSSPSSWithSHA256 {
			t.Fatalf("%s: server signed with %v", VersionName(v), got)
		}
		if got := server.ConnectionState().testingOnlyPeerSignatureAlgorithm; got != PSSPSSWithSHA256 {
			t.Fatalf("%s: client signed with %v", VersionName(v), got)
		}
	}
	// A peer that does not offer rsa_pss_pss cannot be served with a PSS key.
	cc, sc := xConfigs(t, p.pss)
	cc.Certificates = nil
	sc.ClientAuth = NoClientCert
	if _, _, err := xPair(t, cc, sc); err == nil {
		t.Fatal("PSS key used without rsa_pss_pss offered")
	}
}

func TestBrainpool(t *testing.T) {
	p := testPKI(t)
	t.Run("TLS 1.2 ECDHE and ECDSA", func(t *testing.T) {
		for _, g := range []CurveID{BrainpoolP256r1, BrainpoolP384r1, BrainpoolP512r1} {
			cc, sc := xConfigs(t, p.bp256)
			cc.MaxVersion = VersionTLS12
			cc.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}
			cc.CurvePreferences, sc.CurvePreferences = []CurveID{g}, []CurveID{CurveP256, g}
			client, server, err := xPair(t, cc, sc)
			if err != nil {
				t.Fatalf("%v: %v", g, err)
			}
			if cs := client.ConnectionState(); cs.CurveID != g {
				t.Fatalf("group %v", cs.CurveID)
			}
			go echo(server)
			roundTrip(t, client, "bp")
		}
	})
	t.Run("TLS 1.3", func(t *testing.T) {
		cc, sc := xConfigs(t, p.bp256)
		cc.MinVersion = VersionTLS13
		schemes := []SignatureScheme{ECDSABrainpoolP256r1TLS13WithSHA256, ECDSAWithP256AndSHA256, PSSWithSHA256}
		cc.Ext.SignatureSchemes, sc.Ext.SignatureSchemes = schemes, schemes
		cc.CurvePreferences, sc.CurvePreferences = []CurveID{BrainpoolP256r1TLS13}, []CurveID{BrainpoolP256r1TLS13}
		client, _, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		cs := client.ConnectionState()
		if cs.CurveID != BrainpoolP256r1TLS13 || cs.testingOnlyPeerSignatureAlgorithm != ECDSABrainpoolP256r1TLS13WithSHA256 {
			t.Fatalf("group %v scheme %v", cs.CurveID, cs.testingOnlyPeerSignatureAlgorithm)
		}
	})
	t.Run("brainpool not offered in TLS 1.2 by default", func(t *testing.T) {
		cc, sc := xConfigs(t, p.rsa)
		cc.MaxVersion = VersionTLS12
		sc.CurvePreferences = []CurveID{BrainpoolP256r1}
		if _, _, err := xPair(t, cc, sc); err == nil {
			t.Fatal("brainpool negotiated without the client offering it")
		}
	})
}

// recordSizes wraps a conn and records the plaintext lengths it sees on
// the wire (record header lengths).
type recordSizes struct {
	net.Conn
	mu  sync.Mutex
	buf []byte
	max int
}

func (r *recordSizes) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	r.mu.Lock()
	r.buf = append(r.buf, b[:n]...)
	for len(r.buf) >= 5 {
		l := int(r.buf[3])<<8 | int(r.buf[4])
		if len(r.buf) < 5+l {
			break
		}
		if l > r.max {
			r.max = l
		}
		r.buf = r.buf[5+l:]
	}
	r.mu.Unlock()
	return n, err
}

func TestMaxFragmentLength(t *testing.T) {
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		cc, sc := xConfigs(t, testPKI(t).ecdsa)
		cc.MaxVersion = v
		cc.Ext.MaxFragmentLength = 1 // 512 bytes
		c, s := localPipe(t)
		wc, ws := &recordSizes{Conn: c}, &recordSizes{Conn: s}
		client, server := Client(wc, cc), Server(ws, sc)
		defer client.Close()
		defer server.Close()
		go echo(server)
		if err := client.Handshake(); err != nil {
			t.Fatalf("%s: %v", VersionName(v), err)
		}
		if got := client.ConnectionState().Ext.MaxFragmentLength; got != 512 {
			t.Fatalf("%s: limit %d", VersionName(v), got)
		}
		// The hellos come before the limit applies.
		wc.mu.Lock()
		wc.max = 0
		wc.mu.Unlock()
		ws.mu.Lock()
		ws.max = 0
		ws.mu.Unlock()
		roundTrip(t, client, string(bytes.Repeat([]byte("m"), 5000)))
		// Ciphertext may exceed 512 by the AEAD overhead (and, in TLS
		// 1.2, the explicit nonce).
		wc.mu.Lock()
		cmax := wc.max
		wc.mu.Unlock()
		ws.mu.Lock()
		smax := ws.max
		ws.mu.Unlock()
		if cmax > 512+64 || smax > 512+64 {
			t.Fatalf("%s: records of %d (from server) and %d (from client) bytes", VersionName(v), cmax, smax)
		}
		if cmax < 256 {
			t.Fatalf("%s: suspiciously small records (%d)", VersionName(v), cmax)
		}
	}
}

type mapSessionCache struct {
	mu sync.Mutex
	m  map[string]*SessionState
}

func (c *mapSessionCache) Get(id string) (*SessionState, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.m[id]
	return s, ok
}

func (c *mapSessionCache) Put(id string, s *SessionState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[id] = s
}

func TestServerSessionIDResumption(t *testing.T) {
	cc, sc := xConfigs(t, testPKI(t).ecdsa)
	cc.MaxVersion = VersionTLS12
	cache := &mapSessionCache{m: map[string]*SessionState{}}
	sc.Ext.ServerSessionCache = cache
	sc.SessionTicketsDisabled = true
	cc.ClientSessionCache = NewLRUClientSessionCache(4)
	cc.Ext.ClientSessionIDs = true
	client, _, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().DidResume || len(cache.m) != 1 {
		t.Fatalf("first handshake resumed or not cached (%d)", len(cache.m))
	}
	client2, _, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if !client2.ConnectionState().DidResume {
		t.Fatal("session ID not resumed")
	}
}

func TestOCSPStaplingV2AndChain(t *testing.T) {
	p := testPKI(t)
	leaf := p.rsa.cert
	leaf.OCSPStaple = []byte("leaf-ocsp")
	leaf.ChainOCSPStaples = [][]byte{[]byte("ca-ocsp")}
	t.Run("TLS 1.2 status_request_v2", func(t *testing.T) {
		cc, sc := xConfigs(t, p.rsa)
		sc.Certificates = []Certificate{leaf}
		cc.MaxVersion = VersionTLS12
		cc.Ext.RequestOCSPMulti = true
		client, _, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		cs := client.ConnectionState()
		if len(cs.Ext.OCSPResponses) != 2 || string(cs.Ext.OCSPResponses[1]) != "ca-ocsp" || string(cs.OCSPResponse) != "leaf-ocsp" {
			t.Fatalf("responses %q", cs.Ext.OCSPResponses)
		}
	})
	t.Run("TLS 1.2 status_request only", func(t *testing.T) {
		cc, sc := xConfigs(t, p.rsa)
		sc.Certificates = []Certificate{leaf}
		cc.MaxVersion = VersionTLS12
		client, _, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		if cs := client.ConnectionState(); string(cs.OCSPResponse) != "leaf-ocsp" || len(cs.Ext.OCSPResponses) != 1 {
			t.Fatalf("%q", cs.Ext.OCSPResponses)
		}
	})
	t.Run("TLS 1.3 per certificate", func(t *testing.T) {
		cc, sc := xConfigs(t, p.rsa)
		sc.Certificates = []Certificate{leaf}
		clientLeaf := p.client.cert
		clientLeaf.OCSPStaple = []byte("client-ocsp")
		clientLeaf.ChainOCSPStaples = [][]byte{[]byte("client-ca-ocsp")}
		cc.Certificates = []Certificate{clientLeaf}
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		if cs := client.ConnectionState(); len(cs.Ext.OCSPResponses) != 2 || string(cs.Ext.OCSPResponses[1]) != "ca-ocsp" {
			t.Fatalf("client saw %q", cs.Ext.OCSPResponses)
		}
		if ss := server.ConnectionState(); len(ss.Ext.OCSPResponses) != 2 || string(ss.Ext.OCSPResponses[0]) != "client-ocsp" {
			t.Fatalf("server saw %q", ss.Ext.OCSPResponses)
		}
	})
}

func TestTrustedCAKeys(t *testing.T) {
	p := testPKI(t)
	list, err := TrustedAuthoritiesFor([][]byte{p.caCert.Raw})
	if err != nil {
		t.Fatal(err)
	}
	var seen []TrustedAuthority
	cc, sc := xConfigs(t, p.rsa)
	cc.MaxVersion = VersionTLS12
	cc.Ext.TrustedCAKeys = list
	sc.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		seen = chi.Ext.TrustedCAKeys
		return nil, nil
	}
	client, _, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0].Type != TrustedKeySHA1Hash || seen[1].Type != TrustedX509Name {
		t.Fatalf("server saw %v", seen)
	}
	if !client.ConnectionState().Ext.TrustedCAKeysAcknowledged {
		t.Fatal("server did not acknowledge a matching CA")
	}
	// Another CA: no acknowledgement.
	other := []TrustedAuthority{{Type: TrustedX509Name, Data: p.rsa.x509.RawSubject}}
	if TrustedAuthoritiesMatch(p.rsa.cert.Certificate[:1], other) {
		t.Fatal("leaf subject matched as an issuer")
	}
	cc.Ext.TrustedCAKeys = []TrustedAuthority{{Type: TrustedCertSHA1Hash, Data: make([]byte, 20)}}
	client, _, err = xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if client.ConnectionState().Ext.TrustedCAKeysAcknowledged {
		t.Fatal("acknowledged without a match")
	}
	if _, err := parseTrustedAuthorities([]byte{1, 2, 3}); err == nil {
		t.Fatal("malformed list parsed")
	}
}

func TestCertificateAuthoritiesAndPSKModes(t *testing.T) {
	p := testPKI(t)
	cc, sc := xConfigs(t, p.rsa)
	cc.Ext.CertificateAuthorities = [][]byte{p.caCert.RawSubject}
	cc.ClientSessionCache = NewLRUClientSessionCache(2)
	var cas [][]byte
	var modes []uint8
	sc.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) {
		cas, modes = chi.Ext.CertificateAuthorities, chi.Ext.PSKModes
		return nil, nil
	}
	client, _, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(cas) != 1 || !bytes.Equal(cas[0], p.caCert.RawSubject) {
		t.Fatalf("server saw %x", cas)
	}
	if !slices.Equal(modes, []uint8{pskModeDHE}) {
		t.Fatalf("psk modes %v", modes)
	}
	got := client.ConnectionState().Ext.PeerCertificateAuthorities
	if len(got) != 1 || !bytes.Equal(got[0], p.caCert.RawSubject) {
		t.Fatalf("client saw CertificateRequest CAs %x", got)
	}
}

func TestCCM8AndIntegrityOnlySuites(t *testing.T) {
	for _, id := range []uint16{TLS_AES_128_CCM_8_SHA256, TLS_SHA256_SHA256, TLS_SHA384_SHA384} {
		cc, sc := xConfigs(t, testPKI(t).ecdsa)
		cc.MinVersion = VersionTLS13
		cc.Ext.CipherSuitesTLS13 = []uint16{id}
		sc.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_128_GCM_SHA256, id}
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatalf("%s: %v", CipherSuiteName(id), err)
		}
		if got := client.ConnectionState().CipherSuite; got != id {
			t.Fatalf("negotiated %s", CipherSuiteName(got))
		}
		go echo(server)
		roundTrip(t, client, string(bytes.Repeat([]byte("i"), 20000)))
		if err := client.SendKeyUpdate(true); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, client, "after update")
		// Off unless listed: a default server does not accept them.
		cc2, sc2 := xConfigs(t, testPKI(t).ecdsa)
		cc2.Ext.CipherSuitesTLS13 = []uint16{id}
		if _, _, err := xPair(t, cc2, sc2); err == nil {
			t.Fatalf("%s accepted by a default server", CipherSuiteName(id))
		}
	}
	// RFC 9150 5: the record is the plaintext and the HMAC, nothing hidden;
	// a changed byte is refused.
	a := aeadHMACSHA256(bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32))
	seq := []byte{0, 0, 0, 0, 0, 0, 0, 5}
	rec := a.Seal(nil, seq, []byte("visible"), []byte("hdr"))
	if !bytes.HasPrefix(rec, []byte("visible")) || len(rec) != 7+32 {
		t.Fatalf("record %x", rec)
	}
	if p, err := a.Open(nil, seq, rec, []byte("hdr")); err != nil || string(p) != "visible" {
		t.Fatal(p, err)
	}
	rec[0] ^= 1
	if _, err := a.Open(nil, seq, rec, []byte("hdr")); err == nil {
		t.Fatal("changed record accepted")
	}
	if !IsIntegrityOnly(TLS_SHA384_SHA384) || IsIntegrityOnly(TLS_AES_128_CCM_8_SHA256) {
		t.Fatal("IsIntegrityOnly")
	}
}

func TestNewValueNames(t *testing.T) {
	for v, want := range map[fmt.Stringer]string{
		FFDHE2048: "FFDHE2048", BrainpoolP256r1TLS13: "BrainpoolP256r1TLS13", BrainpoolP384r1: "BrainpoolP384r1",
		PSSPSSWithSHA256: "PSSPSSWithSHA256", ECDSABrainpoolP512r1TLS13WithSHA512: "ECDSABrainpoolP512r1TLS13WithSHA512",
		CurveP256: "CurveP256", PSSWithSHA256: "PSSWithSHA256",
	} {
		if got := v.String(); got != want {
			t.Errorf("%v: %q", want, got)
		}
	}
	for _, id := range []uint16{TLS_AES_128_CCM_8_SHA256, TLS_SHA256_SHA256, TLS_SHA384_SHA384, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256} {
		if strings.HasPrefix(CipherSuiteName(id), "0x") {
			t.Errorf("%#04x has no name", id)
		}
	}
}

// An RSASSA-PSS key as CA key: a PSS CA (self-signed with RSASSA-PSS)
// issues a PSS-key leaf; chains verify through a pool filled by
// AppendCertsFromPEM, in a handshake too.
func TestRSAPSSCAKey(t *testing.T) {
	now := time.Now()
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "PSS CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, SignatureAlgorithm: x509.SHA256WithRSAPSS}
	caDER, err := pssCertificate(caTmpl, caTmpl, caKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ParseCertificate(caDER)
	if err != nil || !IsRSAPSSKey(ca) {
		t.Fatalf("CA %v", err)
	}
	leafKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(101), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, SignatureAlgorithm: x509.SHA256WithRSAPSS}
	leafDER, err := pssCertificate(leafTmpl, ca, caKey, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	pool := x509.NewCertPool()
	if !AppendCertsFromPEM(pool, caPEM) {
		t.Fatal("pool")
	}
	leaf, _ := ParseCertificate(leafDER)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost"}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// crypto/x509's own pool cannot use the PSS CA.
	plain := x509.NewCertPool()
	plain.AppendCertsFromPEM(caPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: plain, DNSName: "localhost"}); err == nil {
		t.Log("crypto/x509 verified a PSS CA itself (fine, but unexpected)")
	}
	cert := Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}
	schemes := []SignatureScheme{PSSPSSWithSHA256, PSSWithSHA256, ECDSAWithP256AndSHA256}
	cc := &Config{RootCAs: pool, ServerName: "localhost", Ext: ConfigExt{SignatureSchemes: schemes}}
	sc := &Config{Certificates: []Certificate{cert}, Ext: ConfigExt{SignatureSchemes: schemes}}
	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		cc.MaxVersion = v
		if _, _, err := xPair(t, cc, sc); err != nil {
			t.Fatalf("%s: %v", VersionName(v), err)
		}
	}
}

func TestRSANullSHA256(t *testing.T) {
	cc, sc := xConfigs(t, testPKI(t).rsa)
	cc.MaxVersion = VersionTLS12
	cc.CipherSuites, sc.CipherSuites = []uint16{TLS_RSA_WITH_NULL_SHA256}, []uint16{TLS_RSA_WITH_NULL_SHA256}
	cc.Ext.RequireEncryptThenMAC, sc.Ext.RequireEncryptThenMAC = true, true // not a CBC suite: no effect
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if cs := client.ConnectionState(); cs.CipherSuite != TLS_RSA_WITH_NULL_SHA256 || cs.Ext.EncryptThenMAC || !IsIntegrityOnly(cs.CipherSuite) {
		t.Fatalf("%+v", cs)
	}
	go echo(server)
	roundTrip(t, client, string(bytes.Repeat([]byte("n"), 20000)))
	// Plaintext on the wire, HMAC-SHA256 after it; a changed byte fails.
	w := &halfConn{version: VersionTLS12, cipher: nullStream{}, mac: macSHA256(bytes.Repeat([]byte{3}, 32))}
	r := &halfConn{version: VersionTLS12, cipher: nullStream{}, mac: macSHA256(bytes.Repeat([]byte{3}, 32))}
	rec, err := w.encrypt([]byte{byte(recordTypeApplicationData), 3, 3, 0, 0}, []byte("clear"), nil)
	if err != nil || !bytes.Contains(rec, []byte("clear")) || len(rec) != 5+5+32 {
		t.Fatalf("%x %v", rec, err)
	}
	bad := slices.Clone(rec)
	bad[6] ^= 1
	if _, _, err := r.decrypt(bad); err != alertBadRecordMAC {
		t.Fatal("changed record accepted")
	}
	// Off by default.
	cc2, sc2 := xConfigs(t, testPKI(t).rsa)
	cc2.MaxVersion = VersionTLS12
	cc2.CipherSuites = []uint16{TLS_RSA_WITH_NULL_SHA256}
	if _, _, err := xPair(t, cc2, sc2); err == nil {
		t.Fatal("accepted by a default server")
	}
}

// A renegotiation may not change the use of the extended master secret
// (found by BoGo's ExtendedMasterSecret-Renego-Downgrade and -Upgrade,
// which also run the check end to end).
func TestRenegotiationEMSChange(t *testing.T) {
	for _, tc := range []struct {
		handshakes int
		had, got   bool
		refused    bool
	}{
		{0, false, true, false}, // first handshake: anything goes
		{0, false, false, false},
		{1, true, true, false},
		{1, false, false, false},
		{1, true, false, true}, // downgrade
		{2, false, true, true}, // upgrade
	} {
		err := renegotiationEMSError(tc.handshakes, tc.had, tc.got)
		if (err != nil) != tc.refused {
			t.Errorf("handshakes %d, EMS %v then %v: got %v, refused %v", tc.handshakes, tc.had, tc.got, err, tc.refused)
		}
	}
}

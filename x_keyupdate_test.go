// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"crypto/tls"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Tests of Config.Ext.MinKeyUpdateInterval: timed KeyUpdates from an idle
// peer count as progress, fast ones still count against the limit of
// non-advancing records. The OpenSSL interoperability test is
// TestOpenSSLKeyUpdateIdle in x_openssl_test.go.

// errNonAdvancing is Go's error text for the limit (conn.go,
// handlePostHandshakeMessage), checked as the expected result.
const errNonAdvancing = "tls: too many non-advancing records"

// kuHarness is a TLS 1.3 connection pair where one side (sender) sends
// KeyUpdates and the other (receiver) reads, on a clock the test sets.
type kuHarness struct {
	t                *testing.T
	sender, receiver *Conn
	base             time.Time
	now              atomic.Int64 // offset from base, nanoseconds
	processed        chan struct{}
	readErr          chan error
	data             chan string
}

// newKUHarness makes the pair. With serverSends the server sends the
// updates and the client reads.
func newKUHarness(t *testing.T, interval time.Duration, serverSends bool) *kuHarness {
	t.Helper()
	h := &kuHarness{t: t, base: time.Now(), processed: make(chan struct{}, 1000),
		readErr: make(chan error, 1), data: make(chan string, 10)}
	clock := func() time.Time { return h.base.Add(time.Duration(h.now.Load())) }
	cc, sc := xConfigs(t, testPKI(t).rsa)
	cc.MinVersion, sc.MinVersion = VersionTLS13, VersionTLS13
	sc.SessionTicketsDisabled = true // no NewSessionTicket in the count
	cc.Time, sc.Time = clock, clock
	rcfg := sc
	if serverSends {
		rcfg = cc
	}
	rcfg.Ext.MinKeyUpdateInterval = interval
	rcfg.Ext.Observer = func(_ *Conn, e Event) {
		if e.Kind == EventKeyUpdateReceived {
			h.processed <- struct{}{}
		}
	}
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	h.sender, h.receiver = client, server
	if serverSends {
		h.sender, h.receiver = server, client
	}
	go func() {
		buf := make([]byte, 256)
		for {
			n, err := h.receiver.Read(buf)
			if n > 0 {
				h.data <- string(buf[:n])
			}
			if err != nil {
				h.readErr <- err
				return
			}
		}
	}()
	return h
}

// update sends a KeyUpdate at offset at from the handshake and waits
// until the receiver has processed it; it returns the receiver's read
// error if the receiver closed the connection instead.
func (h *kuHarness) update(at time.Duration) error {
	h.t.Helper()
	h.now.Store(int64(at))
	if err := h.sender.SendKeyUpdate(false); err != nil {
		h.t.Fatalf("SendKeyUpdate: %v", err)
	}
	select {
	case <-h.processed:
		return nil
	case err := <-h.readErr:
		return err
	case <-time.After(10 * time.Second):
		h.t.Fatal("receiver did not process the KeyUpdate")
	}
	return nil
}

// mustUpdate is update expecting the receiver to keep the connection,
// with its count of non-advancing records then at want.
func (h *kuHarness) mustUpdate(at time.Duration, want int) {
	h.t.Helper()
	if err := h.update(at); err != nil {
		h.t.Fatalf("KeyUpdate at %v: receiver closed: %v", at, err)
	}
	// The observer's channel send orders this read after the receiver's
	// write; the receiver touches the count again only on the next record.
	if got := h.receiver.retryCount; got != want {
		h.t.Fatalf("KeyUpdate at %v: %d non-advancing records counted, want %d", at, got, want)
	}
}

// mustDrop is update expecting the receiver to close the connection.
func (h *kuHarness) mustDrop(at time.Duration) {
	h.t.Helper()
	err := h.update(at)
	if err == nil || err.Error() != errNonAdvancing {
		h.t.Fatalf("KeyUpdate at %v: got %v, want %q", at, err, errNonAdvancing)
	}
}

// data sends application data and checks that the receiver gets it.
func (h *kuHarness) roundData(msg string) {
	h.t.Helper()
	if _, err := h.sender.Write([]byte(msg)); err != nil {
		h.t.Fatal(err)
	}
	select {
	case got := <-h.data:
		if got != msg {
			h.t.Fatalf("got %q, want %q", got, msg)
		}
	case err := <-h.readErr:
		h.t.Fatalf("receiver: %v", err)
	case <-time.After(10 * time.Second):
		h.t.Fatal("no data")
	}
}

func bothRoles(t *testing.T, f func(t *testing.T, serverSends bool)) {
	t.Run("client sends", func(t *testing.T) { f(t, false) })
	t.Run("server sends", func(t *testing.T) { f(t, true) })
}

// An idle peer renewing its keys every 2 minutes, received with half
// that as the minimum interval, survives 60 updates without data.
func TestMinKeyUpdateIntervalIdlePeer(t *testing.T) {
	bothRoles(t, func(t *testing.T, serverSends bool) {
		h := newKUHarness(t, time.Minute, serverSends)
		const n = 60
		for i := 1; i <= n; i++ {
			h.mustUpdate(time.Duration(i)*2*time.Minute, 0)
		}
		h.roundData("still here")
		if got := h.receiver.ConnectionState().Ext.KeyUpdatesReceived; got != n {
			t.Fatalf("%d KeyUpdates received, want %d", got, n)
		}
	})
}

// A flood faster than the interval is refused at the upstream limit: 16
// are ignored, the 17th closes the connection.
func TestMinKeyUpdateIntervalFlood(t *testing.T) {
	bothRoles(t, func(t *testing.T, serverSends bool) {
		h := newKUHarness(t, time.Minute, serverSends)
		for i := 1; i <= maxUselessRecords; i++ {
			h.mustUpdate(time.Duration(i)*time.Second, i)
		}
		h.mustDrop(17 * time.Second)
	})
	// A flood right after a timely update: that one counts as progress,
	// the flood still does not.
	t.Run("after a timely update", func(t *testing.T) {
		h := newKUHarness(t, time.Minute, false)
		h.mustUpdate(time.Minute, 0)
		for i := 1; i <= maxUselessRecords; i++ {
			h.mustUpdate(time.Minute+time.Duration(i)*time.Millisecond, i)
		}
		h.mustDrop(time.Minute + time.Second)
	})
	// Without a clock step at all.
	t.Run("same instant", func(t *testing.T) {
		h := newKUHarness(t, time.Minute, false)
		for i := 1; i <= maxUselessRecords; i++ {
			h.mustUpdate(0, i)
		}
		h.mustDrop(0)
	})
}

func TestMinKeyUpdateIntervalMixed(t *testing.T) {
	const min = time.Minute
	// The boundary, measured from the handshake for the first update and
	// from the previous update that counted afterwards: a fast update does
	// not move the reference.
	t.Run("boundary", func(t *testing.T) {
		h := newKUHarness(t, min, false)
		h.mustUpdate(min-time.Nanosecond, 1) // too soon after the handshake
		h.mustUpdate(min, 1)                 // exactly min after the handshake: progress
		h.mustUpdate(2*min-time.Nanosecond, 2)
		h.mustUpdate(2*min, 2)
		h.mustUpdate(3*min+time.Second, 2)
	})
	// Fast updates between timely ones add up; the count is not reset by
	// a timely update, only by application data (as upstream).
	t.Run("bursts add up", func(t *testing.T) {
		h := newKUHarness(t, min, false)
		count := 0
		for round := 1; round <= 5; round++ {
			at := time.Duration(round) * 2 * min
			h.mustUpdate(at, count)
			for j := 1; j <= 3; j++ {
				count++
				h.mustUpdate(at+time.Duration(j)*time.Second, count)
			}
		}
		if count != 15 {
			t.Fatalf("count %d", count)
		}
		h.mustUpdate(12*min, 15)
		h.mustUpdate(12*min+time.Second, 16)
		h.mustDrop(12*min + 2*time.Second)
	})
	// Application data resets the count, as upstream; timely updates keep
	// the connection up on either side of it.
	t.Run("data resets", func(t *testing.T) {
		h := newKUHarness(t, min, true)
		for i := 1; i <= 10; i++ {
			h.mustUpdate(time.Duration(i)*time.Second, i)
		}
		h.roundData("reset")
		for i := 1; i <= maxUselessRecords; i++ {
			h.mustUpdate(10*time.Second+time.Duration(i)*time.Millisecond, i)
		}
		h.roundData("reset again")
		for i := 1; i <= 50; i++ {
			h.mustUpdate(time.Duration(i)*min, 0)
		}
		h.mustUpdate(50*min+time.Second, 1)
		h.roundData("done")
	})
}

// With the zero value (and a negative one) timed updates are counted as
// upstream: the 17th closes the connection, however far apart they are.
func TestMinKeyUpdateIntervalDefault(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Minute} {
		bothRoles(t, func(t *testing.T, serverSends bool) {
			h := newKUHarness(t, interval, serverSends)
			for i := 1; i <= maxUselessRecords; i++ {
				h.mustUpdate(time.Duration(i)*time.Hour, i)
			}
			h.mustDrop(17 * time.Hour)
		})
	}
}

// The default behaves as the Go toolchain's crypto/tls: a tlsx client
// sends n KeyUpdates and then data; tlsx (default Config) and crypto/tls
// servers accept 16 and refuse 17 with the same error.
func TestMinKeyUpdateIntervalDefaultMatchesCryptoTLS(t *testing.T) {
	leaf := testPKI(t).rsa
	run := func(t *testing.T, n int, stdlib bool) error {
		c, s := localPipe(t)
		cc, sc := xConfigs(t, leaf)
		cc.MinVersion = VersionTLS13
		cc.Certificates = nil
		client := Client(c, cc)
		t.Cleanup(func() { client.Close() })
		var server interface {
			Handshake() error
			Read([]byte) (int, error)
			Close() error
		}
		if stdlib {
			server = tls.Server(s, &tls.Config{
				Certificates:           []tls.Certificate{{Certificate: leaf.cert.Certificate, PrivateKey: leaf.cert.PrivateKey}},
				MinVersion:             tls.VersionTLS13,
				SessionTicketsDisabled: true,
			})
		} else {
			sc.ClientAuth, sc.MinVersion, sc.SessionTicketsDisabled = NoClientCert, VersionTLS13, true
			server = Server(s, sc)
		}
		t.Cleanup(func() { server.Close() })
		errc := make(chan error, 1)
		go func() { errc <- server.Handshake() }()
		if err := client.Handshake(); err != nil {
			t.Fatal(err)
		}
		if err := <-errc; err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			if err := client.SendKeyUpdate(false); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := client.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		s.SetReadDeadline(time.Now().Add(10 * time.Second))
		_, err := server.Read(make([]byte, 1))
		return err
	}
	for _, n := range []int{maxUselessRecords, maxUselessRecords + 1} {
		goErr, ourErr := run(t, n, true), run(t, n, false)
		if (goErr == nil) != (ourErr == nil) || goErr != nil && goErr.Error() != ourErr.Error() {
			t.Fatalf("%d KeyUpdates: crypto/tls %v, tlsx %v", n, goErr, ourErr)
		}
		if n > maxUselessRecords && (ourErr == nil || !strings.Contains(ourErr.Error(), "non-advancing")) {
			t.Fatalf("%d KeyUpdates accepted: %v", n, ourErr)
		}
		if n <= maxUselessRecords && ourErr != nil {
			t.Fatalf("%d KeyUpdates refused: %v", n, ourErr)
		}
	}
}

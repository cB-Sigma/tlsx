// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/testports"
)

// Interoperability with OpenSSL 3 (s_server and s_client) as an
// independent peer, for every feature tlsx adds that OpenSSL implements.
// OPENSSL INTEROP TESTS: they run only when an OpenSSL 3 "openssl" is on
// PATH and TLSX_SKIP_INTEROP is not set; otherwise they are skipped.
// (OpenSSL implements neither status_request_v2 nor trusted_ca_keys;
// those are tested Go to Go in x_features_test.go.)

func opensslBin(t *testing.T) string {
	t.Helper()
	if os.Getenv("TLSX_SKIP_INTEROP") != "" {
		t.Skip("OPENSSL INTEROP: TLSX_SKIP_INTEROP is set")
	}
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("OPENSSL INTEROP: openssl not on PATH")
	}
	out, err := exec.Command(p, "version").Output()
	if err != nil || !bytes.HasPrefix(out, []byte("OpenSSL 3.")) {
		t.Skipf("OPENSSL INTEROP: %s is not OpenSSL 3 (%q)", p, bytes.TrimSpace(out))
	}
	return p
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// osslProc is a running s_server or s_client.
type osslProc struct {
	t     *testing.T
	cmd   *exec.Cmd
	stdin io.WriteCloser
	out   *syncBuf
}

func startOpenSSL(t *testing.T, args ...string) *osslProc {
	t.Helper()
	bin := opensslBin(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	cmd := exec.CommandContext(ctx, bin, args...)
	out := &syncBuf{}
	cmd.Stdout, cmd.Stderr = out, out
	stdin, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	p := &osslProc{t: t, cmd: cmd, stdin: stdin, out: out}
	t.Cleanup(func() {
		stdin.Close()
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("openssl %s output:\n%s", strings.Join(args, " "), out.String())
		}
	})
	return p
}

// send writes a line of data to the process's stdin.
func (p *osslProc) send(line string) {
	p.t.Helper()
	if _, err := io.WriteString(p.stdin, line+"\n"); err != nil {
		p.t.Fatalf("stdin: %v", err)
	}
}

// command sends an s_server/s_client command letter ("K", "R", "r"). The
// tools take a line as a command only if it arrives alone in one read, so
// the input pauses around it.
func (p *osslProc) command(letter string) {
	p.t.Helper()
	time.Sleep(300 * time.Millisecond)
	p.send(letter)
	time.Sleep(300 * time.Millisecond)
}

func (p *osslProc) waitFor(what string) {
	p.t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(p.out.String(), what) {
		if time.Now().After(deadline) {
			p.t.Fatalf("openssl did not print %q; output:\n%s", what, p.out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	// testports: never released between choosing and binding.
	return testports.TCPPort(t)
}

// pkiFiles writes the test PKI for OpenSSL.
func pkiFiles(t *testing.T) map[string]string {
	p := testPKI(t)
	return writeFiles(t, map[string][]byte{
		"ca.pem":        p.caPEM,
		"rsa.pem":       p.rsa.certPEM,
		"rsa.key":       p.rsa.keyPEM,
		"ecdsa.pem":     p.ecdsa.certPEM,
		"ecdsa.key":     p.ecdsa.keyPEM,
		"pss.pem":       p.pss.certPEM,
		"pss.key":       p.pss.keyPEM,
		"bp.pem":        p.bp256.certPEM,
		"bp.key":        p.bp256.keyPEM,
		"client.pem":    p.client.certPEM,
		"client.key":    p.client.keyPEM,
		"rsachain.pem":  append(append([]byte(nil), p.rsa.certPEM...), p.caPEM...),
		"clientCAs.pem": p.caPEM,
	})
}

// sServer starts s_server for one connection and returns its port.
func sServer(t *testing.T, f map[string]string, cert, key string, args ...string) (*osslProc, int) {
	port := freePort(t)
	a := append([]string{"s_server", "-accept", "127.0.0.1:" + strconv.Itoa(port), "-naccept", "1",
		"-cert", f[cert], "-key", f[key]}, args...)
	p := startOpenSSL(t, a...)
	p.waitFor("ACCEPT")
	return p, port
}

// goClient dials s_server with cfg.
func goClient(t *testing.T, port int, cfg *Config) *Conn {
	t.Helper()
	d := &net.Dialer{Timeout: 10 * time.Second}
	c, err := DialWithDialer(d, "tcp", "127.0.0.1:"+strconv.Itoa(port), cfg)
	if err != nil {
		t.Fatalf("dial OpenSSL: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// goServer accepts one connection with cfg and hands it over after the
// handshake; the s_client arguments follow -connect.
func goServer(t *testing.T, cfg *Config, clientArgs ...string) (*osslProc, *Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got := make(chan *Conn, 1)
	errc := make(chan error, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			errc <- err
			return
		}
		c := Server(raw, cfg)
		c.SetDeadline(time.Now().Add(20 * time.Second))
		if err := c.Handshake(); err != nil {
			c.Close()
			errc <- err
			return
		}
		c.SetDeadline(time.Time{})
		got <- c
	}()
	a := append([]string{"s_client", "-connect", l.Addr().String()}, clientArgs...)
	p := startOpenSSL(t, a...)
	select {
	case c := <-got:
		t.Cleanup(func() { c.Close() })
		return p, c
	case err := <-errc:
		t.Fatalf("handshake with s_client: %v\n%s", err, p.out.String())
	case <-time.After(30 * time.Second):
		t.Fatalf("no handshake with s_client:\n%s", p.out.String())
	}
	return nil, nil
}

// goServerFails expects the handshake with s_client to fail.
func goServerFails(t *testing.T, cfg *Config, clientArgs ...string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	errc := make(chan error, 1)
	go func() {
		raw, err := l.Accept()
		if err != nil {
			errc <- err
			return
		}
		c := Server(raw, cfg)
		c.SetDeadline(time.Now().Add(20 * time.Second))
		errc <- c.Handshake()
		c.Close()
	}()
	p := startOpenSSL(t, append([]string{"s_client", "-connect", l.Addr().String()}, clientArgs...)...)
	if err := <-errc; err == nil {
		t.Fatalf("handshake with s_client succeeded:\n%s", p.out.String())
	}
}

// readUntil reads from c until it has read want (other data is kept).
func readUntil(t *testing.T, c *Conn, want string) {
	t.Helper()
	if err := readUntilErr(c, want); err != nil {
		t.Fatal(err)
	}
}

// readUntilErr is readUntil for another goroutine than the test's.
func readUntilErr(c *Conn, want string) error {
	c.SetReadDeadline(time.Now().Add(20 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var got []byte
	buf := make([]byte, 4096)
	for !bytes.Contains(got, []byte(want)) {
		n, err := c.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			return fmt.Errorf("reading %q: got %q, %v", want, got, err)
		}
	}
	return nil
}

func clientCfg(t *testing.T) *Config {
	p := testPKI(t)
	return &Config{RootCAs: p.pool, ServerName: "localhost", Certificates: []Certificate{p.client.cert}}
}

func serverCfg(t *testing.T, leaf xLeaf) *Config {
	p := testPKI(t)
	return &Config{Certificates: []Certificate{leaf.cert}, ClientCAs: p.pool, ClientAuth: RequireAndVerifyClientCert}
}

func sClientAuth(f map[string]string) []string {
	return []string{"-CAfile", f["ca.pem"], "-verify_return_error", "-servername", "localhost", "-cert", f["client.pem"], "-key", f["client.key"]}
}

func TestOpenSSLKeyUpdate(t *testing.T) {
	f := pkiFiles(t)
	t.Run("Go client, s_server", func(t *testing.T) {
		srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_3")
		c := goClient(t, port, clientCfg(t))
		// Our update, asking OpenSSL to update too.
		if err := c.SendKeyUpdate(true); err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("go-after-own-update\n"))
		srv.waitFor("go-after-own-update")
		srv.send("from-openssl-1")
		readUntil(t, c, "from-openssl-1")
		if s := c.ConnectionState().Ext; s.KeyUpdatesSent != 1 || s.KeyUpdatesReceived != 1 {
			t.Fatalf("sent %d received %d", s.KeyUpdatesSent, s.KeyUpdatesReceived)
		}
		// OpenSSL's update with update_requested ("K").
		srv.command("K")
		srv.send("from-openssl-2")
		readUntil(t, c, "from-openssl-2")
		c.Write([]byte("go-after-answer\n"))
		srv.waitFor("go-after-answer")
		if s := c.ConnectionState().Ext; s.KeyUpdatesSent != 2 || s.KeyUpdatesReceived != 2 {
			t.Fatalf("sent %d received %d", s.KeyUpdatesSent, s.KeyUpdatesReceived)
		}
	})
	t.Run("s_client, Go server", func(t *testing.T) {
		cl, c := goServer(t, serverCfg(t, testPKI(t).rsa), append(sClientAuth(f), "-tls1_3")...)
		cl.waitFor("Verify return code: 0")
		cl.command("K")
		cl.waitFor("KEYUPDATE")
		cl.send("from-client-1")
		readUntil(t, c, "from-client-1")
		if s := c.ConnectionState().Ext; s.KeyUpdatesReceived != 1 || s.KeyUpdatesSent != 1 {
			t.Fatalf("server received %d sent %d", s.KeyUpdatesReceived, s.KeyUpdatesSent)
		}
		if err := c.SendKeyUpdate(true); err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("from-go-server\n"))
		cl.waitFor("from-go-server")
		cl.send("from-client-2")
		readUntil(t, c, "from-client-2")
		if s := c.ConnectionState().Ext; s.KeyUpdatesReceived != 2 || s.KeyUpdatesSent != 2 {
			t.Fatalf("server received %d sent %d", s.KeyUpdatesReceived, s.KeyUpdatesSent)
		}
	})
}

// OpenSSL sends KeyUpdates ("k": update_not_requested) about every 600 ms
// with no data. Go's limit on non-advancing records drops it; with
// Config.Ext.MinKeyUpdateInterval below that period the connection
// survives, and data still flows afterwards.
func TestOpenSSLKeyUpdateIdle(t *testing.T) {
	const updates = 24 // well past maxUselessRecords
	f := pkiFiles(t)
	// idle has p send KeyUpdates while c reads; it returns the number sent
	// and c's read error, if c gave up.
	idle := func(t *testing.T, p *osslProc, c *Conn) (int, error) {
		readErr := make(chan error, 1)
		got := make(chan struct{}, 1)
		go func() {
			c.SetReadDeadline(time.Now().Add(50 * time.Second))
			buf := make([]byte, 256)
			var in []byte
			for {
				n, err := c.Read(buf)
				in = append(in, buf[:n]...)
				if bytes.Contains(in, []byte("alive-after-updates")) {
					got <- struct{}{}
					return
				}
				if err != nil {
					readErr <- err
					return
				}
			}
		}()
		for i := 1; i <= updates; i++ {
			time.Sleep(300 * time.Millisecond)
			select {
			case err := <-readErr:
				return i - 1, err
			default:
			}
			p.send("k")
			time.Sleep(300 * time.Millisecond)
		}
		// (s_client prints KEYUPDATE, s_server prints nothing; the count
		// Go received is checked instead.)
		p.send("alive-after-updates")
		select {
		case <-got:
			return updates, nil
		case err := <-readErr:
			return updates, err
		case <-time.After(20 * time.Second):
			t.Fatal("no data after the updates")
		}
		return 0, nil
	}
	check := func(t *testing.T, c *Conn, sent int, err error, withOption bool) {
		t.Helper()
		received := c.ConnectionState().Ext.KeyUpdatesReceived
		t.Logf("OpenSSL sent %d KeyUpdates; Go received %d; read error: %v", sent, received, err)
		if withOption {
			if err != nil || received != updates {
				t.Fatalf("with MinKeyUpdateInterval: %d of %d updates, %v", received, updates, err)
			}
			return
		}
		if err == nil || !strings.Contains(err.Error(), "too many non-advancing records") {
			t.Fatalf("without MinKeyUpdateInterval the connection survived %d updates (%v)", received, err)
		}
		if received > maxUselessRecords {
			t.Fatalf("without MinKeyUpdateInterval %d updates were accepted", received)
		}
	}
	for _, withOption := range []bool{false, true} {
		name := "default"
		if withOption {
			name = "MinKeyUpdateInterval"
		}
		t.Run("s_server sends, Go client, "+name, func(t *testing.T) {
			srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_3")
			cfg := clientCfg(t)
			if withOption {
				cfg.Ext.MinKeyUpdateInterval = 250 * time.Millisecond
			}
			c := goClient(t, port, cfg)
			sent, err := idle(t, srv, c)
			check(t, c, sent, err, withOption)
		})
		t.Run("s_client sends, Go server, "+name, func(t *testing.T) {
			cfg := serverCfg(t, testPKI(t).rsa)
			if withOption {
				cfg.Ext.MinKeyUpdateInterval = 250 * time.Millisecond
			}
			cl, c := goServer(t, cfg, append(sClientAuth(f), "-tls1_3")...)
			cl.waitFor("Verify return code: 0")
			sent, err := idle(t, cl, c)
			check(t, c, sent, err, withOption)
		})
	}
}

func TestOpenSSLRenegotiation(t *testing.T) {
	f := pkiFiles(t)
	renegClient := func() *Config {
		cfg := clientCfg(t)
		cfg.MaxVersion = VersionTLS12
		cfg.Renegotiation = RenegotiateFreelyAsClient
		return cfg
	}
	t.Run("Go client starts, s_server accepts", func(t *testing.T) {
		srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_2", "-client_renegotiation")
		cfg := renegClient()
		cfg.ClientSessionCache = NewLRUClientSessionCache(2)
		var verified int
		var mu sync.Mutex
		cfg.VerifyConnection = func(ConnectionState) error { mu.Lock(); verified++; mu.Unlock(); return nil }
		c := goClient(t, port, cfg)
		if !c.ConnectionState().Ext.SecureRenegotiation {
			t.Fatal("OpenSSL did not signal RFC 5746")
		}
		if err := c.Renegotiate(); err != nil {
			t.Fatalf("Renegotiate: %v", err)
		}
		c.Write([]byte("after-full-renegotiation\n"))
		srv.waitFor("after-full-renegotiation")
		if err := c.Resume(); err != nil {
			t.Fatalf("Resume: %v", err)
		}
		c.Write([]byte("after-resumption\n"))
		srv.waitFor("after-resumption")
		cs := c.ConnectionState()
		if cs.Ext.Handshakes != 3 || !cs.DidResume {
			t.Fatalf("handshakes %d resumed %v", cs.Ext.Handshakes, cs.DidResume)
		}
		mu.Lock()
		defer mu.Unlock()
		if verified != 3 {
			t.Fatalf("certificate checks: %d", verified)
		}
		srv.send("from-openssl")
		readUntil(t, c, "from-openssl")
	})
	t.Run("s_server refuses client renegotiation", func(t *testing.T) {
		srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_2")
		c := goClient(t, port, renegClient())
		if err := c.Renegotiate(); !errors.Is(err, ErrRenegotiationRefusedByPeer) {
			t.Fatalf("got %v", err)
		}
		c.Write([]byte("still-usable\n"))
		srv.waitFor("still-usable")
	})
	t.Run("s_server asks (HelloRequest)", func(t *testing.T) {
		srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_2")
		c := goClient(t, port, renegClient())
		srv.command("r")
		srv.send("after-hello-request")
		readUntil(t, c, "after-hello-request")
		if n := c.ConnectionState().Ext.Handshakes; n != 2 {
			t.Fatalf("%d handshakes", n)
		}
		c.Write([]byte("renegotiated-client\n"))
		srv.waitFor("renegotiated-client")
	})
	t.Run("s_client starts, Go server accepts", func(t *testing.T) {
		cfg := serverCfg(t, testPKI(t).rsa)
		cfg.Ext.AcceptRenegotiation = true
		var log eventLog
		cfg.Ext.Observer = log.add
		cl, c := goServer(t, cfg, append(sClientAuth(f), "-tls1_2")...)
		cl.waitFor("Verify return code: 0")
		cl.command("R")
		cl.send("after-client-renegotiation")
		readUntil(t, c, "after-client-renegotiation")
		if n := c.ConnectionState().Ext.Handshakes; n != 2 {
			t.Fatalf("%d handshakes", n)
		}
		if e, ok := log.last(EventRenegotiated); !ok || !e.ByPeer {
			t.Fatal("event")
		}
		c.Write([]byte("from-go\n"))
		cl.waitFor("from-go")
	})
	t.Run("s_client refused by Go server", func(t *testing.T) {
		var log eventLog
		cfg := serverCfg(t, testPKI(t).rsa)
		cfg.Ext.Observer = log.add
		cl, c := goServer(t, cfg, append(sClientAuth(f), "-tls1_2")...)
		cl.waitFor("Verify return code: 0")
		cl.command("R")
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 64)
		c.Read(b)
		if c.ConnectionState().Ext.Handshakes != 1 || log.count(EventRenegotiationRefused) != 1 {
			t.Fatalf("handshakes %d, refused events %d", c.ConnectionState().Ext.Handshakes, log.count(EventRenegotiationRefused))
		}
	})
	t.Run("Go server asks s_client (HelloRequest)", func(t *testing.T) {
		done := make(chan struct{})
		cfg := serverCfg(t, testPKI(t).rsa)
		cfg.Ext.Observer = func(_ *Conn, e Event) {
			t.Logf("event %+v", e) // shown on failure
			if e.Kind == EventRenegotiated {
				close(done)
			}
		}
		cl, c := goServer(t, cfg, append(sClientAuth(f), "-tls1_2")...)
		cl.waitFor("Verify return code: 0")
		if err := c.RequestRenegotiation(); err != nil {
			t.Fatal(err)
		}
		c.Write([]byte("hello-request-sent\n"))
		cl.waitFor("hello-request-sent")
		// s_client answers the HelloRequest by itself; the ClientHello is
		// processed while we read. After that handshake s_client sits in a
		// blocking SSL_read and reads no input until a record arrives, so a
		// line typed then was lost now and then (a timeout under load). We
		// wait for the renegotiation, send data first, then type.
		read := make(chan error, 1)
		go func() { read <- readUntilErr(c, "after-server-renegotiation") }()
		select {
		case <-done:
		case err := <-read:
			t.Fatalf("read before the renegotiation completed: %v", err)
		case <-time.After(20 * time.Second):
			t.Fatal("s_client did not renegotiate")
		}
		if _, err := c.Write([]byte("server-renegotiated\n")); err != nil {
			t.Fatal(err)
		}
		cl.waitFor("server-renegotiated")
		cl.send("after-server-renegotiation")
		if err := <-read; err != nil {
			t.Fatal(err)
		}
		if n := c.ConnectionState().Ext.Handshakes; n != 2 {
			t.Fatalf("%d handshakes", n)
		}
	})
}

func TestOpenSSLDHE(t *testing.T) {
	f := pkiFiles(t)
	bin := opensslBin(t)
	params := func(name string, args ...string) string {
		p := f["ca.pem"] + "." + name
		out, err := exec.Command(bin, append([]string{"genpkey", "-genparam", "-algorithm", "DH", "-out", p}, args...)...).CombinedOutput()
		if err != nil {
			t.Fatalf("genpkey: %v %s", err, out)
		}
		return p
	}
	ff2048 := params("ffdhe2048", "-pkeyopt", "group:ffdhe2048")
	t.Run("Go client, s_server ffdhe2048", func(t *testing.T) {
		srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_2", "-cipher", "DHE-RSA-AES128-GCM-SHA256", "-dhparam", ff2048)
		cfg := clientCfg(t)
		cfg.CipherSuites = []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}
		cfg.CurvePreferences = []CurveID{FFDHE2048, CurveP256}
		c := goClient(t, port, cfg)
		if cs := c.ConnectionState(); cs.CipherSuite != TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 || cs.CurveID != FFDHE2048 {
			t.Fatalf("suite %s group %v", CipherSuiteName(cs.CipherSuite), cs.CurveID)
		}
		c.Write([]byte("dhe-data\n"))
		srv.waitFor("dhe-data")
	})
	t.Run("Go client refuses a custom group", func(t *testing.T) {
		custom := params("custom1024", "-pkeyopt", "dh_paramgen_prime_len:1024")
		// Security level 0: OpenSSL itself refuses a 1024-bit group otherwise.
		_, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_2", "-cipher", "DHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", "-dhparam", custom)
		cfg := clientCfg(t)
		cfg.CipherSuites = []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}
		cfg.CurvePreferences = []CurveID{FFDHE2048, CurveP256}
		_, err := DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(port), cfg)
		if err == nil || !strings.Contains(err.Error(), "RFC 7919") {
			t.Fatalf("custom group: %v", err)
		}
	})
	t.Run("s_client, Go server", func(t *testing.T) {
		cfg := serverCfg(t, testPKI(t).rsa)
		cfg.CipherSuites = []uint16{TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DHE_RSA_WITH_AES_128_GCM_SHA256}
		cfg.CurvePreferences = []CurveID{FFDHE3072, FFDHE2048}
		cl, c := goServer(t, cfg, append(sClientAuth(f), "-tls1_2", "-cipher", "DHE-RSA-AES256-GCM-SHA384")...)
		cl.waitFor("Verify return code: 0")
		if cs := c.ConnectionState(); cs.CipherSuite != TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 || !isFFDHE(cs.CurveID) {
			t.Fatalf("suite %s group %v", CipherSuiteName(cs.CipherSuite), cs.CurveID)
		}
		cl.send("dhe-from-openssl")
		readUntil(t, c, "dhe-from-openssl")
	})
}

func TestOpenSSLFFDHE2048TLS13(t *testing.T) {
	f := pkiFiles(t)
	srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_3", "-groups", "ffdhe2048")
	cfg := clientCfg(t)
	cfg.CurvePreferences = []CurveID{FFDHE2048}
	c := goClient(t, port, cfg)
	if cs := c.ConnectionState(); cs.CurveID != FFDHE2048 || cs.Version != VersionTLS13 {
		t.Fatalf("group %v", cs.CurveID)
	}
	c.Write([]byte("ffdhe13\n"))
	srv.waitFor("ffdhe13")

	scfg := serverCfg(t, testPKI(t).rsa)
	scfg.CurvePreferences = []CurveID{FFDHE2048, CurveP256}
	cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_3", "-groups", "ffdhe2048")...)
	cl.waitFor("Verify return code: 0")
	if sc.ConnectionState().CurveID != FFDHE2048 {
		t.Fatalf("group %v", sc.ConnectionState().CurveID)
	}
	cl.send("ffdhe13-client")
	readUntil(t, sc, "ffdhe13-client")
}

func TestOpenSSLAES128CCM(t *testing.T) {
	f := pkiFiles(t)
	srv, port := sServer(t, f, "ecdsa.pem", "ecdsa.key", "-tls1_3", "-ciphersuites", "TLS_AES_128_CCM_SHA256")
	cfg := clientCfg(t)
	cfg.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_128_CCM_SHA256}
	c := goClient(t, port, cfg)
	if c.ConnectionState().CipherSuite != TLS_AES_128_CCM_SHA256 {
		t.Fatal("suite")
	}
	big := strings.Repeat("c", 20000)
	c.Write([]byte(big + "\n"))
	srv.waitFor(big)
	srv.send("ccm-back")
	readUntil(t, c, "ccm-back")

	scfg := serverCfg(t, testPKI(t).ecdsa)
	scfg.Ext.CipherSuitesTLS13 = []uint16{TLS_AES_128_CCM_SHA256}
	cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_3", "-ciphersuites", "TLS_AES_128_CCM_SHA256")...)
	cl.waitFor("TLS_AES_128_CCM_SHA256")
	cl.send("ccm-client")
	readUntil(t, sc, "ccm-client")
	sc.Write([]byte("ccm-server\n"))
	cl.waitFor("ccm-server")
}

func TestOpenSSLEncryptThenMAC(t *testing.T) {
	f := pkiFiles(t)
	for _, tc := range []struct {
		ossl, cert, key string
		id              uint16
	}{
		{"AES128-SHA256", "rsa.pem", "rsa.key", TLS_RSA_WITH_AES_128_CBC_SHA256},
		{"ECDHE-ECDSA-AES256-SHA384", "ecdsa.pem", "ecdsa.key", TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384},
		{"ECDHE-RSA-AES128-SHA256", "rsa.pem", "rsa.key", TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256},
	} {
		t.Run(tc.ossl, func(t *testing.T) {
			srv, port := sServer(t, f, tc.cert, tc.key, "-tls1_2", "-cipher", tc.ossl)
			cfg := clientCfg(t)
			cfg.CipherSuites = []uint16{tc.id}
			cfg.Ext.RequireEncryptThenMAC = true
			c := goClient(t, port, cfg)
			if cs := c.ConnectionState(); !cs.Ext.EncryptThenMAC || cs.CipherSuite != tc.id {
				t.Fatal("encrypt_then_mac not negotiated with OpenSSL")
			}
			msg := strings.Repeat("etm", 3000)
			c.Write([]byte(msg + "\n"))
			srv.waitFor(msg)
			srv.send("etm-back")
			readUntil(t, c, "etm-back")

			leaf := testPKI(t).rsa
			if strings.HasPrefix(tc.cert, "ecdsa") {
				leaf = testPKI(t).ecdsa
			}
			scfg := serverCfg(t, leaf)
			scfg.CipherSuites = []uint16{tc.id}
			scfg.Ext.RequireEncryptThenMAC = true
			cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_2", "-cipher", tc.ossl)...)
			cl.waitFor("Verify return code: 0")
			if !sc.ConnectionState().Ext.EncryptThenMAC {
				t.Fatal("server side: no encrypt_then_mac")
			}
			cl.send("etm-client")
			readUntil(t, sc, "etm-client")
			// s_client without encrypt_then_mac is refused (IEC 62351-3 7.5.7).
			goServerFails(t, scfg, append(sClientAuth(f), "-tls1_2", "-cipher", tc.ossl, "-no_etm")...)
		})
	}
}

func TestOpenSSLRSAPSSPSS(t *testing.T) {
	f := pkiFiles(t)
	schemes := []SignatureScheme{PSSPSSWithSHA256, PSSPSSWithSHA384, PSSWithSHA256, ECDSAWithP256AndSHA256}
	for _, v := range []string{"-tls1_2", "-tls1_3"} {
		t.Run(v, func(t *testing.T) {
			// OpenSSL server with the PSS-key certificate, only rsa_pss_pss.
			srv, port := sServer(t, f, "pss.pem", "pss.key", v, "-sigalgs", "rsa_pss_pss_sha256:rsa_pss_pss_sha384")
			cfg := clientCfg(t)
			cfg.Ext.SignatureSchemes = schemes
			c := goClient(t, port, cfg)
			if got := c.ConnectionState().testingOnlyPeerSignatureAlgorithm; got != PSSPSSWithSHA256 && got != PSSPSSWithSHA384 {
				t.Fatalf("OpenSSL signed with %v", got)
			}
			c.Write([]byte("pss\n"))
			srv.waitFor("pss")

			// Go server with the PSS key, s_client allowing only rsa_pss_pss.
			scfg := serverCfg(t, testPKI(t).pss)
			scfg.Ext.SignatureSchemes = schemes
			// rsa_pss_rsae too, for s_client's own (rsaEncryption) client
			// certificate; our PSS key can only sign rsa_pss_pss.
			cl, sc := goServer(t, scfg, append(sClientAuth(f), v, "-sigalgs", "rsa_pss_pss_sha256:rsa_pss_rsae_sha256")...)
			cl.waitFor("Verify return code: 0")
			cl.send("pss-client")
			readUntil(t, sc, "pss-client")
		})
	}
}

func TestOpenSSLBrainpool(t *testing.T) {
	f := pkiFiles(t)
	t.Run("TLS 1.2", func(t *testing.T) {
		srv, port := sServer(t, f, "bp.pem", "bp.key", "-tls1_2", "-groups", "brainpoolP256r1", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256")
		cfg := clientCfg(t)
		cfg.CurvePreferences = []CurveID{BrainpoolP256r1, CurveP256}
		c := goClient(t, port, cfg)
		if c.ConnectionState().CurveID != BrainpoolP256r1 {
			t.Fatalf("group %v", c.ConnectionState().CurveID)
		}
		c.Write([]byte("bp12\n"))
		srv.waitFor("bp12")

		scfg := serverCfg(t, testPKI(t).bp256)
		scfg.CurvePreferences = []CurveID{BrainpoolP256r1, BrainpoolP384r1, CurveP256}
		scfg.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256}
		cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_2", "-groups", "brainpoolP384r1:brainpoolP256r1")...) // the certificate's curve must be listed (RFC 8422 5.1)
		cl.waitFor("Verify return code: 0")
		if sc.ConnectionState().CurveID != BrainpoolP384r1 {
			t.Fatalf("group %v", sc.ConnectionState().CurveID)
		}
		cl.send("bp12-client")
		readUntil(t, sc, "bp12-client")
	})
	t.Run("TLS 1.3", func(t *testing.T) {
		schemes := []SignatureScheme{ECDSABrainpoolP256r1TLS13WithSHA256, ECDSAWithP256AndSHA256, PSSWithSHA256}
		srv, port := sServer(t, f, "bp.pem", "bp.key", "-tls1_3", "-groups", "brainpoolP256r1tls13", "-sigalgs", "ecdsa_brainpoolP256r1_sha256")
		cfg := clientCfg(t)
		cfg.CurvePreferences = []CurveID{BrainpoolP256r1TLS13}
		cfg.Ext.SignatureSchemes = schemes
		c := goClient(t, port, cfg)
		if cs := c.ConnectionState(); cs.CurveID != BrainpoolP256r1TLS13 || cs.testingOnlyPeerSignatureAlgorithm != ECDSABrainpoolP256r1TLS13WithSHA256 {
			t.Fatalf("group %v scheme %v", cs.CurveID, cs.testingOnlyPeerSignatureAlgorithm)
		}
		c.Write([]byte("bp13\n"))
		srv.waitFor("bp13")

		scfg := serverCfg(t, testPKI(t).bp256)
		scfg.CurvePreferences = []CurveID{BrainpoolP256r1TLS13}
		scfg.Ext.SignatureSchemes = schemes
		cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_3", "-groups", "brainpoolP256r1tls13", "-sigalgs", "ecdsa_brainpoolP256r1_sha256:rsa_pss_rsae_sha256")...)
		cl.waitFor("Verify return code: 0")
		cl.send("bp13-client")
		readUntil(t, sc, "bp13-client")
	})
}

func TestOpenSSLMaxFragmentLength(t *testing.T) {
	f := pkiFiles(t)
	scfg := serverCfg(t, testPKI(t).ecdsa)
	cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_2", "-maxfraglen", "512")...)
	cl.waitFor("Verify return code: 0")
	if sc.ConnectionState().Ext.MaxFragmentLength != 512 {
		t.Fatalf("limit %d", sc.ConnectionState().Ext.MaxFragmentLength)
	}
	msg := strings.Repeat("f", 5000)
	sc.Write([]byte(msg + "\n"))
	cl.waitFor(msg) // OpenSSL enforces the limit on what it receives
	cl.send("mfl-client")
	readUntil(t, sc, "mfl-client")

	srv, port := sServer(t, f, "ecdsa.pem", "ecdsa.key", "-tls1_2")
	cfg := clientCfg(t)
	cfg.Ext.MaxFragmentLength = 1
	c := goClient(t, port, cfg)
	if c.ConnectionState().Ext.MaxFragmentLength != 512 {
		t.Fatal("OpenSSL did not accept max_fragment_length")
	}
	c.Write([]byte(msg + "\n"))
	srv.waitFor(msg)
	srv.send(strings.Repeat("g", 3000))
	readUntil(t, c, strings.Repeat("g", 3000))
}

func TestOpenSSLSessionIDResumption(t *testing.T) {
	f := pkiFiles(t)
	cache := &mapSessionCache{m: map[string]*SessionState{}}
	scfg := serverCfg(t, testPKI(t).ecdsa)
	scfg.SessionTicketsDisabled = true
	scfg.Ext.ServerSessionCache = cache
	sess := f["ca.pem"] + ".sess"
	cl, _ := goServer(t, scfg, append(sClientAuth(f), "-tls1_2", "-no_ticket", "-sess_out", sess)...)
	cl.waitFor("Verify return code: 0")
	cl.send("Q")
	time.Sleep(200 * time.Millisecond)
	cl2, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_2", "-no_ticket", "-sess_in", sess)...)
	cl2.waitFor("Reused, TLSv1.2")
	if !sc.ConnectionState().DidResume {
		t.Fatal("server did not resume")
	}

	// Go client resuming by session ID with s_server.
	cfg := clientCfg(t)
	cfg.MaxVersion = VersionTLS12
	cfg.ClientSessionCache = NewLRUClientSessionCache(2)
	cfg.Ext.ClientSessionIDs = true
	_, port := sServer(t, f, "ecdsa.pem", "ecdsa.key", "-tls1_2", "-no_ticket", "-naccept", "2")
	c1 := goClient(t, port, cfg)
	c1.Close()
	c2 := goClient(t, port, cfg)
	if !c2.ConnectionState().DidResume {
		t.Fatal("Go client did not resume by session ID")
	}
}

func TestOpenSSLOCSPChainAndCAs(t *testing.T) {
	f := pkiFiles(t)
	p := testPKI(t)
	now := time.Now()
	resp := func(cert *x509.Certificate) []byte {
		b, err := ocsp.CreateResponse(p.caCert, p.caCert, ocsp.Response{Status: ocsp.Good, SerialNumber: cert.SerialNumber,
			ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, p.caKey)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	leafResp, caResp := resp(p.rsa.x509), resp(p.caCert)
	of := writeFiles(t, map[string][]byte{"leaf.ocsp": leafResp, "ca.ocsp": caResp})
	t.Run("s_server staples the chain to a Go client", func(t *testing.T) {
		_, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_3", "-cert_chain", f["ca.pem"], "-status_all",
			"-status_file", of["leaf.ocsp"], "-status_file", of["ca.ocsp"], "-Verify", "1", "-CAfile", f["ca.pem"])
		c := goClient(t, port, clientCfg(t))
		cs := c.ConnectionState()
		if !bytes.Equal(cs.OCSPResponse, leafResp) {
			t.Fatalf("leaf response %d bytes", len(cs.OCSPResponse))
		}
		// With -status_file, s_server 3.6 staples the leaf response only
		// (seen here); per-certificate chain stapling is checked in the
		// other direction, s_client -ocsp_check_all against our server.
		if len(cs.Ext.OCSPResponses) < 1 || !bytes.Equal(cs.Ext.OCSPResponses[0], leafResp) {
			t.Fatalf("%d responses", len(cs.Ext.OCSPResponses))
		}
		// OpenSSL's CertificateRequest names the CA (certificate_authorities).
		if got := cs.Ext.PeerCertificateAuthorities; len(got) != 1 || !bytes.Equal(got[0], p.caCert.RawSubject) {
			t.Fatalf("CertificateRequest CAs %x", got)
		}
	})
	t.Run("Go server staples the chain to s_client", func(t *testing.T) {
		leaf := p.rsa
		leaf.cert.OCSPStaple = leafResp
		leaf.cert.ChainOCSPStaples = [][]byte{caResp}
		scfg := serverCfg(t, leaf)
		var cas [][]byte
		scfg.GetConfigForClient = func(chi *ClientHelloInfo) (*Config, error) { cas = chi.Ext.CertificateAuthorities; return nil, nil }
		cl, _ := goServer(t, scfg, append(sClientAuth(f), "-tls1_3", "-status", "-ocsp_check_all", "-requestCAfile", f["ca.pem"])...)
		cl.waitFor("Verify return code: 0")
		cl.waitFor("OCSP Response Status: successful")
		if len(cas) != 1 || !bytes.Equal(cas[0], p.caCert.RawSubject) {
			t.Fatalf("certificate_authorities from s_client: %x", cas)
		}
	})
}

var _ = fmt.Sprint
var _ = pem.Decode
var _ = big.NewInt

func TestOpenSSLCCM8AndIntegrityOnly(t *testing.T) {
	f := pkiFiles(t)
	for _, tc := range []struct {
		name string
		id   uint16
	}{{"TLS_AES_128_CCM_8_SHA256", TLS_AES_128_CCM_8_SHA256}, {"TLS_SHA256_SHA256", TLS_SHA256_SHA256}, {"TLS_SHA384_SHA384", TLS_SHA384_SHA384}} {
		t.Run(tc.name, func(t *testing.T) {
			// Security level 0: OpenSSL counts CCM_8 and the integrity-only
			// suites below its default level.
			srv, port := sServer(t, f, "ecdsa.pem", "ecdsa.key", "-tls1_3", "-ciphersuites", tc.name, "-cipher", "ALL:@SECLEVEL=0")
			cfg := clientCfg(t)
			cfg.Ext.CipherSuitesTLS13 = []uint16{tc.id}
			c := goClient(t, port, cfg)
			if c.ConnectionState().CipherSuite != tc.id {
				t.Fatal("suite")
			}
			c.Write([]byte("go-" + tc.name + "\n"))
			srv.waitFor("go-" + tc.name)
			srv.send("ossl-" + tc.name)
			readUntil(t, c, "ossl-"+tc.name)

			scfg := serverCfg(t, testPKI(t).ecdsa)
			scfg.Ext.CipherSuitesTLS13 = []uint16{tc.id}
			cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_3", "-ciphersuites", tc.name, "-cipher", "ALL:@SECLEVEL=0")...)
			cl.waitFor(tc.name)
			cl.send("client-" + tc.name)
			readUntil(t, sc, "client-"+tc.name)
			sc.Write([]byte("server-" + tc.name + "\n"))
			cl.waitFor("server-" + tc.name)
		})
	}
}

// A chain made by OpenSSL whose CA key is RSASSA-PSS: s_server serves it,
// our client verifies it through AppendCertsFromPEM.
func TestOpenSSLRSAPSSCA(t *testing.T) {
	bin := opensslBin(t)
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("openssl %v: %v\n%s", args, err, out)
		}
	}
	run("genpkey", "-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "ca.key")
	run("req", "-x509", "-new", "-key", "ca.key", "-subj", "/CN=OpenSSL PSS CA", "-days", "1", "-out", "ca.pem",
		"-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-1", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=keyCertSign")
	run("genpkey", "-algorithm", "RSA-PSS", "-pkeyopt", "rsa_keygen_bits:2048", "-out", "leaf.key")
	run("req", "-new", "-key", "leaf.key", "-subj", "/CN=localhost", "-out", "leaf.csr")
	if err := os.WriteFile(dir+"/ext.cnf", []byte("subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run("x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "1", "-out", "leaf.pem",
		"-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:-1", "-extfile", "ext.cnf")
	caPEM, _ := os.ReadFile(dir + "/ca.pem")
	pool := x509.NewCertPool()
	if !AppendCertsFromPEM(pool, caPEM) {
		t.Fatal("pool")
	}
	f := map[string]string{"leaf.pem": dir + "/leaf.pem", "leaf.key": dir + "/leaf.key"}
	srv, port := sServer(t, f, "leaf.pem", "leaf.key", "-tls1_3")
	cfg := &Config{RootCAs: pool, ServerName: "localhost",
		Ext: ConfigExt{SignatureSchemes: []SignatureScheme{PSSPSSWithSHA256, PSSWithSHA256, ECDSAWithP256AndSHA256}}}
	c := goClient(t, port, cfg)
	if !IsRSAPSSKey(c.ConnectionState().PeerCertificates[0]) || len(c.ConnectionState().VerifiedChains) != 1 {
		t.Fatal("chain")
	}
	c.Write([]byte("pss-ca\n"))
	srv.waitFor("pss-ca")
}

func TestOpenSSLRSANullSHA256(t *testing.T) {
	f := pkiFiles(t)
	srv, port := sServer(t, f, "rsa.pem", "rsa.key", "-tls1_2", "-cipher", "NULL-SHA256:@SECLEVEL=0")
	cfg := clientCfg(t)
	cfg.CipherSuites = []uint16{TLS_RSA_WITH_NULL_SHA256}
	c := goClient(t, port, cfg)
	if c.ConnectionState().CipherSuite != TLS_RSA_WITH_NULL_SHA256 {
		t.Fatal("suite")
	}
	c.Write([]byte("null-go\n"))
	srv.waitFor("null-go")
	srv.send("null-ossl")
	readUntil(t, c, "null-ossl")

	scfg := serverCfg(t, testPKI(t).rsa)
	scfg.CipherSuites = []uint16{TLS_RSA_WITH_NULL_SHA256}
	cl, sc := goServer(t, scfg, append(sClientAuth(f), "-tls1_2", "-cipher", "NULL-SHA256:@SECLEVEL=0")...)
	cl.waitFor("NULL-SHA256")
	cl.send("null-client")
	readUntil(t, sc, "null-client")
	sc.Write([]byte("null-server\n"))
	cl.waitFor("null-server")
}

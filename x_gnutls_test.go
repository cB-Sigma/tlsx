// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/tlsx/internal/testports"
)

// Interoperability with GnuTLS (gnutls-serv and gnutls-cli) as a second
// independent implementation, for raw public keys (RFC 7250) in TLS 1.2
// and TLS 1.3, both roles. GNUTLS INTEROP TESTS: they run only when
// gnutls-serv and gnutls-cli with raw public key support are on PATH and
// are skipped otherwise.

// gnutlsRPKPriority allows only raw public keys, for both certificates.
const gnutlsRPKPriority = "NORMAL:-CTYPE-ALL:+CTYPE-SRV-RAWPK:+CTYPE-CLI-RAWPK"

func gnutlsBin(t *testing.T, name string) string {
	t.Helper()
	if os.Getenv("TLSX_SKIP_INTEROP") != "" {
		t.Skip("GNUTLS INTEROP: TLSX_SKIP_INTEROP is set")
	}
	p, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("GNUTLS INTEROP: %s not on PATH", name)
	}
	out, _ := exec.Command(p, "--help").CombinedOutput()
	if !bytes.Contains(out, []byte("--rawpkfile")) {
		t.Skipf("GNUTLS INTEROP: %s has no raw public key support", p)
	}
	return p
}

// rpkFiles writes key (PKCS #8) and its SubjectPublicKeyInfo as PEM files.
func rpkFiles(t *testing.T, name string, key crypto.Signer, spki []byte) (keyFile, pubFile string) {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyFile, pubFile = filepath.Join(dir, name+".key"), filepath.Join(dir, name+".pub")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki}), 0o600); err != nil {
		t.Fatal(err)
	}
	return keyFile, pubFile
}

func gnutlsVersionPriority(v uint16) string {
	if v == VersionTLS12 {
		return gnutlsRPKPriority + ":-VERS-ALL:+VERS-TLS1.2"
	}
	return gnutlsRPKPriority + ":-VERS-ALL:+VERS-TLS1.3"
}

func TestGnuTLSRawPublicKeys(t *testing.T) {
	serv := gnutlsBin(t, "gnutls-serv")
	cli := gnutlsBin(t, "gnutls-cli")
	serverKey, serverSPKI := rpkKey(t)
	clientKey, clientSPKI := rpkKey(t)
	srvKeyFile, srvPubFile := rpkFiles(t, "server", serverKey, serverSPKI)
	cliKeyFile, cliPubFile := rpkFiles(t, "client", clientKey, clientSPKI)

	for _, v := range []uint16{VersionTLS12, VersionTLS13} {
		name := VersionName(v)
		t.Run("Go client, gnutls-serv "+name, func(t *testing.T) {
			port := testports.TCPPort(t)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, serv, "--port", strconv.Itoa(port), "--echo", "--require-client-cert",
				"--rawpkkeyfile", srvKeyFile, "--rawpkfile", srvPubFile, "--priority", gnutlsVersionPriority(v))
			var out syncBuf
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			waitListening(t, port, &out)

			cfg := &Config{ServerName: "localhost", MinVersion: v, MaxVersion: v,
				Certificates: []Certificate{RawPublicKeyCertificate(clientKey)},
				Ext:          ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(serverSPKI), RawOnly: true}}}
			c := goClient(t, port, cfg)
			cs := c.ConnectionState()
			if cs.Version != v || !bytes.Equal(cs.Ext.PeerRawPublicKey, serverSPKI) || !cs.Ext.OwnRawPublicKey {
				t.Fatalf("version %x, peer raw key %x, own raw key %v", cs.Version, cs.Ext.PeerRawPublicKey, cs.Ext.OwnRawPublicKey)
			}
			if _, err := c.Write([]byte("rpk-to-gnutls\n")); err != nil {
				t.Fatal(err)
			}
			readUntil(t, c, "rpk-to-gnutls") // gnutls-serv --echo sends it back
		})

		t.Run("gnutls-cli, Go server "+name, func(t *testing.T) {
			got, peer, stdout := gnutlsClientToGo(t, cli, v, cliKeyFile, cliPubFile, serverKey, pin(clientSPKI))
			if got != nil {
				t.Fatalf("Go server: %v\ngnutls-cli:\n%s", got, stdout)
			}
			if !bytes.Equal(peer, clientSPKI) {
				t.Fatalf("peer raw key %x", peer)
			}
			if !strings.Contains(stdout, "Raw Public Key") {
				t.Fatalf("gnutls-cli did not report a raw public key:\n%s", stdout)
			}
		})
	}

	t.Run("Go client refuses an unpinned key from gnutls-serv", func(t *testing.T) {
		port := testports.TCPPort(t)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, serv, "--port", strconv.Itoa(port), "--echo",
			"--rawpkkeyfile", srvKeyFile, "--rawpkfile", srvPubFile, "--priority", gnutlsVersionPriority(VersionTLS13))
		var out syncBuf
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() { cmd.Process.Kill(); cmd.Wait() }()
		waitListening(t, port, &out)
		cfg := &Config{ServerName: "localhost", MinVersion: VersionTLS13,
			Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Verify: pin(clientSPKI), RawOnly: true}}}
		c, err := DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", "127.0.0.1:"+strconv.Itoa(port), cfg)
		if err == nil {
			c.Close()
			t.Fatal("handshake with an unpinned server key succeeded")
		}
	})

	t.Run("Go server refuses an unpinned key from gnutls-cli", func(t *testing.T) {
		_, otherSPKI := rpkKey(t)
		got, _, stdout := gnutlsClientToGo(t, cli, VersionTLS13, cliKeyFile, cliPubFile, serverKey, pin(otherSPKI))
		if got == nil {
			t.Fatalf("handshake with an unpinned client key succeeded\n%s", stdout)
		}
	})
}

// gnutlsClientToGo runs gnutls-cli against a Go server using raw public
// keys and returns the server's handshake or read error, the client's raw
// key as the server saw it and gnutls-cli's output.
func gnutlsClientToGo(t *testing.T, cli string, v uint16, keyFile, pubFile string, serverKey crypto.Signer, verify func([]byte) error) (error, []byte, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	cfg := &Config{MinVersion: v, MaxVersion: v, ClientAuth: RequireAnyClientCert,
		Certificates: []Certificate{RawPublicKeyCertificate(serverKey)},
		Ext:          ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: verify, RawOnly: true}}}
	type result struct {
		err  error
		peer []byte
	}
	res := make(chan result, 1)
	go func() {
		nc, err := l.Accept()
		if err != nil {
			res <- result{err: err}
			return
		}
		c := Server(nc, cfg)
		defer c.Close()
		c.SetDeadline(time.Now().Add(30 * time.Second))
		if err := c.Handshake(); err != nil {
			res <- result{err: err}
			return
		}
		buf := make([]byte, 64)
		var got []byte
		for !bytes.Contains(got, []byte("rpk-from-gnutls")) {
			n, err := c.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				res <- result{err: err}
				return
			}
		}
		res <- result{peer: c.ConnectionState().Ext.PeerRawPublicKey}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// --insecure: gnutls-cli has no pinning option for raw keys; the Go
	// side's verification is what the test checks.
	cmd := exec.CommandContext(ctx, cli, "--port", strconv.Itoa(port), "127.0.0.1", "--insecure",
		"--rawpkkeyfile", keyFile, "--rawpkfile", pubFile, "--priority", gnutlsVersionPriority(v))
	var out syncBuf
	cmd.Stdout, cmd.Stderr = &out, &out
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var r result
	sent := false
	deadline := time.After(30 * time.Second)
	for done := false; !done; {
		select {
		case r = <-res:
			done = true
		case <-time.After(100 * time.Millisecond):
			if !sent && strings.Contains(out.String(), "Handshake was completed") {
				io.WriteString(stdin, "rpk-from-gnutls\n")
				sent = true
			}
		case <-deadline:
			r = result{err: context.DeadlineExceeded}
			done = true
		}
	}
	stdin.Close()
	cmd.Process.Kill()
	cmd.Wait()
	return r.err, r.peer, out.String()
}

// waitListening waits until something accepts on the loopback port.
func waitListening(t *testing.T, port int, out *syncBuf) {
	t.Helper()
	for i := 0; i < 100; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %d:\n%s", port, out.String())
}

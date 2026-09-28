// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"net"
	"strconv"
	"testing"
	"time"
)

// SHA-1 signatures in TLS 1.2 against OpenSSL, which makes them only at
// security level 0 and when told to (-sigalgs, -client_sigalgs). OPENSSL
// INTEROP TEST (see x_openssl_test.go).
func TestOpenSSLSHA1Signatures(t *testing.T) {
	f := pkiFiles(t)
	withGODEBUG(t, "-", "")
	sha1Args := []string{"-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", "-sigalgs", "RSA+SHA1"}

	t.Run("Go client, s_server", func(t *testing.T) {
		srv, port := sServer(t, f, "rsa.pem", "rsa.key", append(sha1Args,
			"-Verify", "1", "-CAfile", f["ca.pem"], "-client_sigalgs", "RSA+SHA1")...)
		cfg := clientCfg(t)
		cfg.Ext.AllowSHA1Signatures = true
		c := goClient(t, port, cfg)
		cs := c.ConnectionState()
		if cs.testingOnlyPeerSignatureAlgorithm != PKCS1WithSHA1 || !cs.Ext.SHA1Signature {
			t.Fatalf("OpenSSL signed with %v, SHA1Signature %v", cs.testingOnlyPeerSignatureAlgorithm, cs.Ext.SHA1Signature)
		}
		// s_server required our certificate (-Verify) and accepted only
		// rsa_pkcs1_sha1 for its CertificateVerify (-client_sigalgs).
		c.Write([]byte("sha1\n"))
		srv.waitFor("sha1")
	})

	t.Run("Go client refuses without the option", func(t *testing.T) {
		_, port := sServer(t, f, "rsa.pem", "rsa.key", sha1Args...)
		d := &net.Dialer{Timeout: 10 * time.Second}
		c, err := DialWithDialer(d, "tcp", "127.0.0.1:"+strconv.Itoa(port), clientCfg(t))
		if err == nil {
			c.Close()
			t.Fatal("handshake with a SHA-1-only s_server succeeded")
		}
	})

	t.Run("Go server, s_client", func(t *testing.T) {
		scfg := serverCfg(t, testPKI(t).rsa)
		scfg.MaxVersion = VersionTLS12
		scfg.Ext.AllowSHA1Signatures = true
		cl, sc := goServer(t, scfg, append(sClientAuth(f), append(sha1Args, "-client_sigalgs", "RSA+SHA1")...)...)
		cs := sc.ConnectionState()
		if cs.testingOnlyPeerSignatureAlgorithm != PKCS1WithSHA1 || !cs.Ext.SHA1Signature {
			t.Fatalf("s_client signed with %v, SHA1Signature %v", cs.testingOnlyPeerSignatureAlgorithm, cs.Ext.SHA1Signature)
		}
		cl.waitFor("Verify return code: 0")
		cl.send("sha1-client")
		readUntil(t, sc, "sha1-client")
	})

	t.Run("Go server refuses without the option", func(t *testing.T) {
		scfg := serverCfg(t, testPKI(t).rsa)
		scfg.ClientAuth = NoClientCert
		goServerFails(t, scfg, append([]string{"-CAfile", f["ca.pem"], "-servername", "localhost"}, sha1Args...)...)
	})
}

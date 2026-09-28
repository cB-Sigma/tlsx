// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// OPENSSL INTEROP TESTS for pre-shared keys and raw public keys, against
// OpenSSL 3 s_server and s_client (skipped without OpenSSL 3 on PATH;
// raw public keys need OpenSSL 3.2 or later).

// sServerPSK starts s_server with a PSK and no certificate.
func sServerPSK(t *testing.T, args ...string) (*osslProc, int) {
	port := freePort(t)
	a := append([]string{"s_server", "-accept", "127.0.0.1:" + strconv.Itoa(port), "-naccept", "1", "-nocert",
		"-psk", hex.EncodeToString(testPSKKey), "-psk_identity", string(testPSKIdentity)}, args...)
	p := startOpenSSL(t, a...)
	p.waitFor("ACCEPT")
	return p, port
}

func sClientPSK(args ...string) []string {
	return append([]string{"-psk", hex.EncodeToString(testPSKKey), "-psk_identity", string(testPSKIdentity), "-servername", "server.tlsx.test"}, args...)
}

// OpenSSL names of the PSK suites both implement (OpenSSL has no RFC
// 8442 ECDHE_PSK AEAD suites).
var opensslPSKSuites = map[uint16]string{
	TLS_PSK_WITH_AES_128_CBC_SHA256:             "PSK-AES128-CBC-SHA256",
	TLS_PSK_WITH_AES_256_CBC_SHA384:             "PSK-AES256-CBC-SHA384",
	TLS_PSK_WITH_AES_128_GCM_SHA256:             "PSK-AES128-GCM-SHA256",
	TLS_PSK_WITH_AES_256_GCM_SHA384:             "PSK-AES256-GCM-SHA384",
	TLS_PSK_WITH_AES_128_CCM:                    "PSK-AES128-CCM",
	TLS_PSK_WITH_AES_128_CCM_8:                  "PSK-AES128-CCM8",
	TLS_PSK_WITH_AES_256_CCM_8:                  "PSK-AES256-CCM8",
	TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:       "PSK-CHACHA20-POLY1305",
	TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:         "DHE-PSK-AES128-GCM-SHA256",
	TLS_DHE_PSK_WITH_AES_128_CBC_SHA256:         "DHE-PSK-AES128-CBC-SHA256",
	TLS_DHE_PSK_WITH_AES_128_CCM:                "DHE-PSK-AES128-CCM",
	TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:   "DHE-PSK-CHACHA20-POLY1305",
	TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:       "ECDHE-PSK-AES128-CBC-SHA256",
	TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384:       "ECDHE-PSK-AES256-CBC-SHA384",
	TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256: "ECDHE-PSK-CHACHA20-POLY1305",
}

func ffdhe2048Params(t *testing.T) string {
	bin := opensslBin(t)
	p := writeFiles(t, map[string][]byte{"x": nil})["x"] + ".dh"
	if out, err := exec.Command(bin, "genpkey", "-genparam", "-algorithm", "DH", "-out", p, "-pkeyopt", "group:ffdhe2048").CombinedOutput(); err != nil {
		t.Fatalf("genpkey: %v %s", err, out)
	}
	return p
}

// TLS 1.2 PSK suites both ways against OpenSSL, TS-0003 v4.8.1 clause
// 10.2.2's TLS_PSK_WITH_AES_128_CBC_SHA256 among them.
func TestOpenSSLPSKTLS12(t *testing.T) {
	opensslBin(t)
	dh := ffdhe2048Params(t)
	for id, name := range opensslPSKSuites {
		cipher := name
		if strings.HasSuffix(name, "CCM8") {
			cipher += ":@SECLEVEL=0" // OpenSSL disables 64-bit tags at its default level
		}
		t.Run("Go client, s_server "+name, func(t *testing.T) {
			srv, port := sServerPSK(t, "-tls1_2", "-cipher", cipher, "-psk_hint", "tlsx-hint", "-dhparam", dh)
			cfg := pskClient(id)
			cfg.CurvePreferences = []CurveID{X25519, CurveP256, FFDHE2048}
			c := goClient(t, port, cfg)
			cs := c.ConnectionState()
			if cs.CipherSuite != id || string(cs.Ext.PSKIdentityHint) != "tlsx-hint" {
				t.Fatalf("suite %s hint %q", CipherSuiteName(cs.CipherSuite), cs.Ext.PSKIdentityHint)
			}
			c.Write([]byte("psk-to-openssl\n"))
			srv.waitFor("psk-to-openssl")
		})
		t.Run("s_client, Go server "+name, func(t *testing.T) {
			cfg := pskServer(id)
			cfg.CurvePreferences = []CurveID{X25519, CurveP256, FFDHE2048}
			cl, c := goServer(t, cfg, sClientPSK("-tls1_2", "-cipher", cipher)...)
			if cs := c.ConnectionState(); cs.CipherSuite != id || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) {
				t.Fatalf("suite %s identity %q", CipherSuiteName(cs.CipherSuite), cs.Ext.PSKIdentity)
			}
			cl.send("psk-from-openssl")
			readUntil(t, c, "psk-from-openssl")
		})
	}
	t.Run("s_client with an unknown identity", func(t *testing.T) {
		goServerFails(t, pskServer(TLS_PSK_WITH_AES_128_CBC_SHA256), "-psk", hex.EncodeToString(testPSKKey),
			"-psk_identity", "nobody", "-tls1_2", "-cipher", "PSK-AES128-CBC-SHA256")
	})
}

// TLS 1.3 external PSKs against OpenSSL: psk_dhe_ke and psk_ke.
func TestOpenSSLPSKTLS13(t *testing.T) {
	opensslBin(t)
	t.Run("Go client, s_server psk_dhe_ke", func(t *testing.T) {
		srv, port := sServerPSK(t, "-tls1_3")
		ccfg, _ := psk13(false, false)
		c := goClient(t, port, ccfg)
		if cs := c.ConnectionState(); cs.Version != VersionTLS13 || cs.CurveID == 0 || cs.Ext.PSKIdentity == nil {
			t.Fatalf("version %x group %v identity %q", cs.Version, cs.CurveID, cs.Ext.PSKIdentity)
		}
		c.Write([]byte("psk13-to-openssl\n"))
		srv.waitFor("psk13-to-openssl")
	})
	t.Run("Go client, s_server psk_ke", func(t *testing.T) {
		srv, port := sServerPSK(t, "-tls1_3", "-allow_no_dhe_kex", "-prefer_no_dhe_kex")
		ccfg, _ := psk13(true, false)
		c := goClient(t, port, ccfg)
		if cs := c.ConnectionState(); cs.CurveID != 0 || cs.Ext.PSKIdentity == nil {
			t.Fatalf("group %v identity %q", cs.CurveID, cs.Ext.PSKIdentity)
		}
		c.Write([]byte("pskke-to-openssl\n"))
		srv.waitFor("pskke-to-openssl")
	})
	t.Run("s_client, Go server psk_dhe_ke", func(t *testing.T) {
		_, scfg := psk13(false, false)
		cl, c := goServer(t, scfg, sClientPSK("-tls1_3")...)
		if cs := c.ConnectionState(); cs.CurveID == 0 || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) {
			t.Fatalf("group %v identity %q", cs.CurveID, cs.Ext.PSKIdentity)
		}
		cl.send("psk13-from-openssl")
		readUntil(t, c, "psk13-from-openssl")
	})
	t.Run("s_client, Go server psk_ke", func(t *testing.T) {
		_, scfg := psk13(true, true)
		cl, c := goServer(t, scfg, sClientPSK("-tls1_3", "-allow_no_dhe_kex")...)
		if cs := c.ConnectionState(); cs.CurveID != 0 {
			t.Fatalf("group %v", cs.CurveID)
		}
		cl.send("pskke-from-openssl")
		readUntil(t, c, "pskke-from-openssl")
	})
}

func spkiOfPEM(t *testing.T, certPEM []byte) []byte {
	b, _ := pem.Decode(certPEM)
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c.RawSubjectPublicKeyInfo
}

// Raw public keys against OpenSSL 3.2+ (-enable_server_rpk,
// -enable_client_rpk), TLS 1.2 and 1.3, both roles.
func TestOpenSSLRawPublicKeys(t *testing.T) {
	bin := opensslBin(t)
	if out, _ := exec.Command(bin, "s_client", "-help").CombinedOutput(); !bytes.Contains(out, []byte("enable_server_rpk")) {
		t.Skip("OPENSSL INTEROP: this OpenSSL has no raw public keys (3.2+)")
	}
	f := pkiFiles(t)
	p := testPKI(t)
	serverSPKI := spkiOfPEM(t, p.ecdsa.certPEM)
	clientSPKI := spkiOfPEM(t, p.client.certPEM)
	for _, v := range []struct {
		flag string
		vers uint16
	}{{"-tls1_2", VersionTLS12}, {"-tls1_3", VersionTLS13}} {
		t.Run("Go client, s_server "+v.flag, func(t *testing.T) {
			srv, port := sServer(t, f, "ecdsa.pem", "ecdsa.key", v.flag, "-enable_server_rpk", "-enable_client_rpk", "-verify", "1")
			cfg := &Config{ServerName: "localhost", MinVersion: v.vers, MaxVersion: v.vers,
				Certificates: []Certificate{RawPublicKeyCertificate(p.client.cert.PrivateKey.(crypto.Signer))},
				Ext:          ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(serverSPKI), RawOnly: true}}}
			c := goClient(t, port, cfg)
			cs := c.ConnectionState()
			if !bytes.Equal(cs.Ext.PeerRawPublicKey, serverSPKI) || !cs.Ext.OwnRawPublicKey {
				t.Fatalf("peer raw key %x own %v", cs.Ext.PeerRawPublicKey, cs.Ext.OwnRawPublicKey)
			}
			c.Write([]byte("rpk-to-openssl\n"))
			srv.waitFor("rpk-to-openssl")
			srv.waitFor("Client raw public key")
		})
		t.Run("s_client, Go server "+v.flag, func(t *testing.T) {
			cfg := &Config{MinVersion: v.vers, MaxVersion: v.vers, ClientAuth: RequireAnyClientCert,
				Certificates: []Certificate{RawPublicKeyCertificate(p.ecdsa.cert.PrivateKey.(crypto.Signer))},
				Ext:          ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(clientSPKI), RawOnly: true}}}
			cl, c := goServer(t, cfg, v.flag, "-enable_server_rpk", "-enable_client_rpk", "-servername", "localhost",
				"-cert", f["client.pem"], "-key", f["client.key"])
			cl.waitFor("Server raw public key")
			if cs := c.ConnectionState(); !bytes.Equal(cs.Ext.PeerRawPublicKey, clientSPKI) {
				t.Fatalf("peer raw key %x", cs.Ext.PeerRawPublicKey)
			}
			cl.send("rpk-from-openssl")
			readUntil(t, c, "rpk-from-openssl")
		})
	}
	t.Run("Go server refuses an unpinned key from s_client", func(t *testing.T) {
		cfg := &Config{MinVersion: VersionTLS12, ClientAuth: RequireAnyClientCert, Certificates: []Certificate{p.ecdsa.cert},
			Ext: ConfigExt{RawPublicKeys: &RawPublicKeyConfig{Send: true, Verify: pin(serverSPKI), RawOnly: true}}}
		goServerFails(t, cfg, "-enable_server_rpk", "-enable_client_rpk", "-cert", f["client.pem"], "-key", f["client.key"])
	})
}

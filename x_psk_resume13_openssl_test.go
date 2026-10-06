// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

// OPENSSL INTEROP TESTS for the resumption of TLS 1.3 external-PSK
// sessions, against OpenSSL 3 s_server and s_client (skipped without
// OpenSSL 3 on PATH).

// resumeClient13 is a Go client with an external PSK and resumption.
func resumeClient13(allowNoDHE bool) *Config {
	cc, _ := psk13(allowNoDHE, false)
	cc.Ext.PSK.Resumption = true
	cc.ClientSessionCache = NewLRUClientSessionCache(2)
	return cc
}

// goClientTicket connects, and reads a line from s_server so the client
// takes the server's NewSessionTicket.
func goClientTicket(t *testing.T, srv *osslProc, port int, cfg *Config, line string) *Conn {
	t.Helper()
	c := goClient(t, port, cfg)
	srv.send(line)
	readUntil(t, c, line)
	return c
}

func TestOpenSSLPSKResumptionTLS13(t *testing.T) {
	opensslBin(t)
	for _, m := range []struct {
		name               string
		server, client     []string
		allowNoDHE, prefer bool
	}{
		{name: "psk_dhe_ke"},
		{name: "psk_ke", server: []string{"-allow_no_dhe_kex", "-prefer_no_dhe_kex"}, client: []string{"-allow_no_dhe_kex"}, allowNoDHE: true, prefer: true},
	} {
		t.Run("Go client, s_server "+m.name, func(t *testing.T) {
			srv, port := sServerPSK(t, append([]string{"-tls1_3", "-naccept", "3"}, m.server...)...)
			cfg := resumeClient13(m.allowNoDHE)
			for i, want := range []bool{false, true, true} {
				c := goClientTicket(t, srv, port, cfg, "ticket-"+string(rune('a'+i)))
				cs := c.ConnectionState()
				if cs.DidResume != want || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) || (cs.CurveID == 0) != m.prefer {
					t.Fatalf("connection %d: resumed %v, identity %q, group %v", i, cs.DidResume, cs.Ext.PSKIdentity, cs.CurveID)
				}
				c.Write([]byte("resumed-to-openssl\n"))
				srv.waitFor("resumed-to-openssl")
				c.Close()
				time.Sleep(100 * time.Millisecond)
			}
		})

		t.Run("Go client falls back to the external PSK with a new s_server "+m.name, func(t *testing.T) {
			cfg := resumeClient13(m.allowNoDHE)
			srv, port := sServerPSK(t, append([]string{"-tls1_3"}, m.server...)...)
			goClientTicket(t, srv, port, cfg, "first").Close()
			if s, ok := cfg.ClientSessionCache.Get(cfg.ServerName); !ok || s == nil {
				t.Fatal("no ticket cached")
			}
			// Another s_server has other ticket keys: it takes the external
			// identity offered after the ticket.
			srv2, port2 := sServerPSK(t, append([]string{"-tls1_3"}, m.server...)...)
			c := goClientTicket(t, srv2, port2, cfg, "second")
			if cs := c.ConnectionState(); cs.DidResume || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) || cs.HelloRetryRequest {
				t.Fatalf("resumed %v, identity %q, HRR %v", cs.DidResume, cs.Ext.PSKIdentity, cs.HelloRetryRequest)
			}
		})

		for _, withPSK := range []bool{true, false} {
			name := "s_client -sess_in with -psk, Go server " + m.name
			if !withPSK {
				name = "s_client -sess_in without -psk, Go server " + m.name
			}
			t.Run(name, func(t *testing.T) {
				_, scfg := psk13(m.allowNoDHE, m.prefer)
				scfg.Ext.PSK.Resumption = true
				sess := writeFiles(t, map[string][]byte{"x": nil})["x"] + ".sess"
				cl, c := goServer(t, scfg, sClientPSK(append([]string{"-tls1_3", "-sess_out", sess}, m.client...)...)...)
				if cs := c.ConnectionState(); cs.DidResume || (cs.CurveID == 0) != m.prefer {
					t.Fatalf("first connection: resumed %v, group %v", cs.DidResume, cs.CurveID)
				}
				c.Write([]byte("first-from-go\n"))
				cl.waitFor("first-from-go")
				waitForFile(t, sess)
				cl.send("Q")
				time.Sleep(200 * time.Millisecond)

				args := []string{"-tls1_3", "-sess_in", sess, "-servername", "server.tlsx.test"}
				if withPSK {
					args = sClientPSK("-tls1_3", "-sess_in", sess)
				}
				cl2, c2 := goServer(t, scfg, append(args, m.client...)...)
				cl2.waitFor("Reused, TLSv1.3")
				cs := c2.ConnectionState()
				if !cs.DidResume || !bytes.Equal(cs.Ext.PSKIdentity, testPSKIdentity) || (cs.CurveID == 0) != m.prefer {
					t.Fatalf("second connection: resumed %v, identity %q, group %v", cs.DidResume, cs.Ext.PSKIdentity, cs.CurveID)
				}
				cl2.send("resumed-from-openssl")
				readUntil(t, c2, "resumed-from-openssl")
			})
		}
	}

	t.Run("Go server refuses s_client's session after the key changed", func(t *testing.T) {
		_, scfg := psk13(false, false)
		scfg.Ext.PSK.Resumption = true
		sess := writeFiles(t, map[string][]byte{"x": nil})["x"] + ".sess"
		cl, c := goServer(t, scfg, sClientPSK("-tls1_3", "-sess_out", sess)...)
		c.Write([]byte("first-from-go\n"))
		cl.waitFor("first-from-go")
		waitForFile(t, sess)
		cl.send("Q")
		time.Sleep(200 * time.Millisecond)
		scfg.Ext.PSK.Lookup = func(_ context.Context, id []byte) ([]byte, error) {
			if bytes.Equal(id, testPSKIdentity) {
				return bytes.Repeat([]byte{9}, 32), nil
			}
			return nil, nil
		}
		goServerFails(t, scfg, "-tls1_3", "-sess_in", sess, "-servername", "server.tlsx.test")
	})
}

func waitForFile(t *testing.T, p string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("s_client wrote no session to %s", p)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

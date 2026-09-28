// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"testing"
)

func TestAuthorizationExtensionsRFC5878(t *testing.T) {
	// Defaults: no authorization extension is offered.
	c := &Conn{config: &Config{ServerName: "example"}, isClient: true}
	hello, _, _, err := c.makeClientHello()
	if err != nil {
		t.Fatal(err)
	}
	if hello.x.clientAuthz != nil || hello.x.serverAuthz != nil {
		t.Fatal("authorization extensions in a default ClientHello")
	}
	p := testPKI(t)
	clientAC, serverAC := []byte("\x30\x03client-ac"), []byte("\x30\x03server-ac")
	cc, sc := xConfigs(t, p.rsa)
	cc.MaxVersion = VersionTLS12
	cc.Ext.AttributeCertificates, cc.Ext.AcceptAttributeCertificates = [][]byte{clientAC}, true
	sc.Ext.AttributeCertificates, sc.Ext.AcceptAttributeCertificates = [][]byte{serverAC}, true
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	go echo(server)
	roundTrip(t, client, "after authz")
	if got := server.ConnectionState().Ext.PeerAttributeCertificates; len(got) != 1 || !bytes.Equal(got[0], clientAC) {
		t.Fatalf("server received %q", got)
	}
	if got := client.ConnectionState().Ext.PeerAttributeCertificates; len(got) != 1 || !bytes.Equal(got[0], serverAC) {
		t.Fatalf("client received %q", got)
	}
	// One direction only: the server does not accept, the client does.
	sc.Ext.AcceptAttributeCertificates = false
	client, server, err = xPair(t, cc, sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(server.ConnectionState().Ext.PeerAttributeCertificates) != 0 || len(client.ConnectionState().Ext.PeerAttributeCertificates) != 1 {
		t.Fatal("client_authz sent although the server did not accept it")
	}
	// Without client certificate authentication.
	cc2, sc2 := xConfigs(t, p.ecdsa)
	cc2.Certificates, sc2.ClientAuth, cc2.MaxVersion = nil, NoClientCert, VersionTLS12
	cc2.Ext.AttributeCertificates = [][]byte{clientAC}
	sc2.Ext.AcceptAttributeCertificates = true
	_, server, err = xPair(t, cc2, sc2)
	if err != nil || len(server.ConnectionState().Ext.PeerAttributeCertificates) != 1 {
		t.Fatalf("without client certificates: %v", err)
	}
	// TLS 1.3: no SupplementalData; the handshake still succeeds.
	cc2.MaxVersion = VersionTLS13
	client, server, err = xPair(t, cc2, sc2)
	if err != nil || client.ConnectionState().Version != VersionTLS13 || len(server.ConnectionState().Ext.PeerAttributeCertificates) != 0 {
		t.Fatalf("TLS 1.3: %v", err)
	}
	// Message encoding round trip and malformed input.
	m := &supplementalDataMsg{attrCerts: [][]byte{clientAC, serverAC}}
	b, err := m.marshal()
	if err != nil {
		t.Fatal(err)
	}
	var back supplementalDataMsg
	if !back.unmarshal(b) || len(back.attrCerts) != 2 || !bytes.Equal(back.attrCerts[1], serverAC) {
		t.Fatalf("round trip %x", b)
	}
	if b[0] != 23 || b[4] != 0 || b[7] != 0x40 || b[8] != 0x02 {
		t.Fatalf("SupplementalData type 23 with an authz_data (16386) entry: % x", b[:10])
	}
	bad := append([]byte(nil), b...)
	bad[13] = 9 // an unknown authorization format
	if (&supplementalDataMsg{}).unmarshal(bad) {
		t.Fatal("unknown format accepted")
	}
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"net"

	"github.com/cB-Sigma/tlsx"
)

// A TLS 1.3 connection authenticated with an external pre-shared key
// (RFC 8446 4.2.11) and no certificates.
func Example_preSharedKey() {
	identity, key := []byte("device-42"), bytes.Repeat([]byte{0x5a}, 32)
	server := &tlsx.Config{MinVersion: tlsx.VersionTLS13, Ext: tlsx.ConfigExt{PSK: &tlsx.PSKConfig{
		TLS13: true,
		Lookup: func(_ context.Context, id []byte) ([]byte, error) {
			if bytes.Equal(id, identity) {
				return key, nil
			}
			return nil, nil // unknown identity
		},
	}}}
	client := &tlsx.Config{ServerName: "gateway.example", MinVersion: tlsx.VersionTLS13,
		Ext: tlsx.ConfigExt{PSK: &tlsx.PSKConfig{TLS13: true, Identity: identity, Key: key}}}

	c, s := net.Pipe()
	go tlsx.Server(s, server).Handshake()
	conn := tlsx.Client(c, client)
	if err := conn.Handshake(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("%s, PSK identity %s\n", tlsx.VersionName(conn.ConnectionState().Version), conn.ConnectionState().Ext.PSKIdentity)
	// Output: TLS 1.3, PSK identity device-42
}

// Raw public keys (RFC 7250): the server presents a bare key, which the
// client trusts by pinning its SubjectPublicKeyInfo.
func Example_rawPublicKeys() {
	serverKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pinned, _ := x509.MarshalPKIXPublicKey(serverKey.Public())

	server := &tlsx.Config{MinVersion: tlsx.VersionTLS13,
		Certificates: []tlsx.Certificate{tlsx.RawPublicKeyCertificate(serverKey)},
		Ext:          tlsx.ConfigExt{RawPublicKeys: &tlsx.RawPublicKeyConfig{Send: true, RawOnly: true}}}
	client := &tlsx.Config{ServerName: "gateway.example", MinVersion: tlsx.VersionTLS13,
		Ext: tlsx.ConfigExt{RawPublicKeys: &tlsx.RawPublicKeyConfig{RawOnly: true,
			Verify: func(spki []byte) error {
				if !bytes.Equal(spki, pinned) {
					return errors.New("unknown server key")
				}
				return nil
			}}}}

	c, s := net.Pipe()
	go tlsx.Server(s, server).Handshake()
	conn := tlsx.Client(c, client)
	if err := conn.Handshake(); err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("server key pinned:", bytes.Equal(conn.ConnectionState().Ext.PeerRawPublicKey, pinned))
	// Output: server key pinned: true
}

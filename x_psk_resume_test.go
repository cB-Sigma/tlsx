// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"bytes"
	"context"
	"sync"
	"testing"
)

// pskKeys is a server's PSK table that a test can change.
type pskKeys struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (k *pskKeys) set(id string, key []byte) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key == nil {
		delete(k.m, id)
	} else {
		k.m[id] = key
	}
}

func (k *pskKeys) lookup(_ context.Context, id []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.m[string(id)], nil
}

func TestPSKResumptionTLS12(t *testing.T) {
	key1, key2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	setup := func(suite uint16, sessionIDs bool) (cc, sc *Config, keys *pskKeys) {
		keys = &pskKeys{m: map[string][]byte{"dev-1": key1}}
		sc = &Config{MinVersion: VersionTLS12, MaxVersion: VersionTLS12, CipherSuites: []uint16{suite},
			CurvePreferences: []CurveID{X25519},
			Ext:              ConfigExt{PSK: &PSKConfig{Hint: []byte("hint"), Lookup: keys.lookup, Resumption: true}}}
		cc = &Config{ServerName: "server.tlsx.test", MinVersion: VersionTLS12, MaxVersion: VersionTLS12, CipherSuites: []uint16{suite},
			CurvePreferences: []CurveID{X25519}, ClientSessionCache: NewLRUClientSessionCache(4),
			Ext: ConfigExt{PSK: &PSKConfig{Identity: []byte("dev-1"), Key: key1, Resumption: true}}}
		if sessionIDs {
			sc.SessionTicketsDisabled, cc.SessionTicketsDisabled = true, true
			sc.Ext.ServerSessionCache = &xBogoSessionCache{m: map[string]*SessionState{}}
			cc.Ext.ClientSessionIDs = true
		}
		return cc, sc, keys
	}
	connect := func(t *testing.T, cc, sc *Config) (resumed bool, err error) {
		t.Helper()
		c, s, err := xPair(t, cc, sc)
		if err != nil {
			return false, err
		}
		for _, cs := range []ConnectionState{c.ConnectionState(), s.ConnectionState()} {
			if string(cs.Ext.PSKIdentity) != string(cc.Ext.PSK.Identity) {
				t.Fatalf("PSK identity %q, want %q", cs.Ext.PSKIdentity, cc.Ext.PSK.Identity)
			}
			if cs.DidResume != c.ConnectionState().DidResume {
				t.Fatal("client and server disagree on resumption")
			}
		}
		exchange(t, c, s)
		return c.ConnectionState().DidResume, nil
	}

	for _, suite := range []uint16{TLS_PSK_WITH_AES_128_GCM_SHA256, TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256, TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, TLS_PSK_WITH_AES_128_CBC_SHA} {
		for _, ids := range []bool{false, true} {
			name := CipherSuiteName(suite) + map[bool]string{false: "/tickets", true: "/session IDs"}[ids]
			t.Run(name, func(t *testing.T) {
				cc, sc, _ := setup(suite, ids)
				sc.CurvePreferences = append(sc.CurvePreferences, FFDHE2048)
				cc.CurvePreferences = append(cc.CurvePreferences, FFDHE2048)
				for i, want := range []bool{false, true, true} {
					resumed, err := connect(t, cc, sc)
					if err != nil || resumed != want {
						t.Fatalf("connection %d: resumed %v, %v; want resumed %v", i, resumed, err, want)
					}
				}
			})
		}
	}

	t.Run("off by default", func(t *testing.T) {
		cc, sc, _ := setup(TLS_PSK_WITH_AES_128_GCM_SHA256, false)
		cc.Ext.PSK.Resumption, sc.Ext.PSK.Resumption = false, false
		for i := 0; i < 2; i++ {
			if resumed, err := connect(t, cc, sc); err != nil || resumed {
				t.Fatalf("connection %d: resumed %v, %v", i, resumed, err)
			}
		}
	})

	t.Run("server refuses after the key is removed", func(t *testing.T) {
		cc, sc, keys := setup(TLS_PSK_WITH_AES_128_GCM_SHA256, false)
		if _, err := connect(t, cc, sc); err != nil {
			t.Fatal(err)
		}
		keys.set("dev-1", nil)
		if resumed, err := connect(t, cc, sc); err == nil || resumed {
			t.Fatalf("resumed %v, %v: want the handshake refused", resumed, err)
		}
	})

	t.Run("server refuses after the key is changed", func(t *testing.T) {
		cc, sc, keys := setup(TLS_PSK_WITH_AES_128_GCM_SHA256, true)
		if _, err := connect(t, cc, sc); err != nil {
			t.Fatal(err)
		}
		keys.set("dev-1", key2) // the client still has key1 and its session
		if resumed, err := connect(t, cc, sc); err == nil || resumed {
			t.Fatalf("resumed %v, %v: want the handshake refused", resumed, err)
		}
	})

	t.Run("client does not offer a session of another key", func(t *testing.T) {
		cc, sc, keys := setup(TLS_PSK_WITH_AES_128_GCM_SHA256, false)
		if _, err := connect(t, cc, sc); err != nil {
			t.Fatal(err)
		}
		// The server would still resume dev-1's session; the client moved
		// on to a new key for the same identity.
		keys.set("dev-1", key1)
		cc.Ext.PSK.Key = key2
		sc.Ext.PSK.Lookup = func(_ context.Context, id []byte) ([]byte, error) {
			if string(id) == "dev-1" {
				return key2, nil // full handshakes use the new key...
			}
			return nil, nil
		}
		resumed, err := connect(t, cc, sc)
		if err != nil || resumed {
			t.Fatalf("resumed %v, %v: want a full handshake with the new key", resumed, err)
		}
	})

	t.Run("client with ClientKey", func(t *testing.T) {
		cc, sc, _ := setup(TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, false)
		var hints []string
		cc.Ext.PSK.Identity, cc.Ext.PSK.Key = nil, nil
		cc.Ext.PSK.ClientKey = func(hint []byte) ([]byte, []byte, error) {
			hints = append(hints, string(hint))
			return []byte("dev-1"), key1, nil
		}
		cc.Ext.PSK.Identity = []byte("dev-1") // for connect's identity check only
		for i, want := range []bool{false, true} {
			if resumed, err := connect(t, cc, sc); err != nil || resumed != want {
				t.Fatalf("connection %d: resumed %v, %v", i, resumed, err)
			}
		}
		if len(hints) != 2 || hints[0] != "hint" || hints[1] != "hint" {
			t.Errorf("ClientKey hints %q, want the server's hint twice", hints)
		}
	})
}

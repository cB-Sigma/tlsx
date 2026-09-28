// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"runtime/debug"
	"testing"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/testenv"
)

func init() { testenv.GODEBUGChanged = godebugReset }

// withGODEBUG sets the GODEBUG environment variable and the build's
// DefaultGODEBUG for the test ("-" leaves GODEBUG unset).
func withGODEBUG(t *testing.T, env, buildDefault string) {
	t.Helper()
	old := readBuildInfo
	t.Cleanup(func() { readBuildInfo = old; godebugReset() })
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "DefaultGODEBUG", Value: buildDefault}}}, true
	}
	if env == "-" {
		t.Setenv("GODEBUG", "")
	} else {
		t.Setenv("GODEBUG", env)
	}
	godebugReset()
}

func TestGODEBUGSources(t *testing.T) {
	for _, tc := range []struct {
		name, env, def string
		want           map[string]string
	}{
		{"environment", "tlssha1=1", "", map[string]string{"tlssha1": "1", "tlsmlkem": ""}},
		{"build default (go.mod godebug, //go:debug)", "-", "tlsmlkem=0,tlssha1=1", map[string]string{"tlsmlkem": "0", "tlssha1": "1"}},
		{"environment over build default", "tlsmlkem=1", "tlsmlkem=0,tlssha1=1", map[string]string{"tlsmlkem": "1", "tlssha1": "1"}},
		{"last occurrence wins", "tlssha1=1,tlssha1=0", "", map[string]string{"tlssha1": "0"}},
		{"absent setting", "http2client=0", "panicnil=1", map[string]string{"tlssha1": "", "tlsmaxrsasize": ""}},
		{"malformed entries ignored", " tlssha1 = 1 ,=x,junk,tlsmaxrsasize=4096", "", map[string]string{"tlsmaxrsasize": "4096"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withGODEBUG(t, tc.env, tc.def)
			for k, v := range tc.want {
				if got := GODEBUGValue(k); got != v {
					t.Errorf("%s = %q, want %q", k, got, v)
				}
			}
		})
	}
}

// The settings are read once: a later change of the environment is not
// seen (a documented difference from Go's own settings).
func TestGODEBUGReadOnce(t *testing.T) {
	withGODEBUG(t, "tlsmaxrsasize=4096", "")
	if got := tlsmaxrsasize.Value(); got != "4096" {
		t.Fatalf("tlsmaxrsasize = %q", got)
	}
	t.Setenv("GODEBUG", "tlsmaxrsasize=2048")
	if got := tlsmaxrsasize.Value(); got != "4096" {
		t.Fatalf("tlsmaxrsasize = %q after os.Setenv, want the first value", got)
	}
}

// tlssha1=1 turns on SHA-1 signatures in TLS 1.2, end to end, and the use
// is counted.
func TestGODEBUGTLSSHA1(t *testing.T) {
	p := testPKI(t)
	sha1Only := func() (*Config, *Config) {
		cc, sc := xConfigs(t, p.rsa)
		cc.MaxVersion = VersionTLS12
		cc.Ext.SignatureSchemes = []SignatureScheme{PKCS1WithSHA1}
		sc.Ext.SignatureSchemes = []SignatureScheme{PKCS1WithSHA1}
		return cc, sc
	}

	withGODEBUG(t, "-", "")
	cc, sc := sha1Only()
	if _, _, err := xPair(t, cc, sc); err == nil {
		t.Fatal("SHA-1-only TLS 1.2 handshake succeeded with GODEBUG unset")
	}

	withGODEBUG(t, "tlssha1=1", "")
	before := GODEBUGNonDefault("tlssha1")
	cc, sc = sha1Only()
	client, server, err := xPair(t, cc, sc)
	if err != nil {
		t.Fatalf("tlssha1=1: %v", err)
	}
	if got := client.ConnectionState().testingOnlyPeerSignatureAlgorithm; got != PKCS1WithSHA1 {
		t.Errorf("server signed with %v", got)
	}
	if got := server.ConnectionState().testingOnlyPeerSignatureAlgorithm; got != PKCS1WithSHA1 {
		t.Errorf("client signed with %v", got)
	}
	if !client.ConnectionState().Ext.SHA1Signature || !server.ConnectionState().Ext.SHA1Signature {
		t.Error("Ext.SHA1Signature not set")
	}
	// Server: own signature and the client's; client: the same.
	if n := GODEBUGNonDefault("tlssha1") - before; n < 4 {
		t.Errorf("tlssha1 non-default uses counted: %d, want at least 4", n)
	}

	// Set in the build's defaults (a go.mod godebug line) it works too.
	withGODEBUG(t, "-", "tlssha1=1")
	cc, sc = sha1Only()
	if _, _, err := xPair(t, cc, sc); err != nil {
		t.Fatalf("DefaultGODEBUG tlssha1=1: %v", err)
	}
}

func TestAllowSHA1Signatures(t *testing.T) {
	withGODEBUG(t, "-", "")
	p := testPKI(t)
	for _, leaf := range []xLeaf{p.rsa, p.ecdsa} {
		name := "RSA"
		scheme := PKCS1WithSHA1
		if leaf.x509.PublicKeyAlgorithm != p.rsa.x509.PublicKeyAlgorithm {
			name, scheme = "ECDSA", ECDSAWithSHA1
		}
		t.Run(name, func(t *testing.T) {
			cfgs := func(clientAllow, serverAllow bool) (*Config, *Config) {
				cc, sc := xConfigs(t, leaf)
				cc.MaxVersion = VersionTLS12
				cc.Ext.SignatureSchemes = []SignatureScheme{scheme, PKCS1WithSHA1}
				sc.Ext.SignatureSchemes = []SignatureScheme{PKCS1WithSHA1}
				cc.Ext.AllowSHA1Signatures, sc.Ext.AllowSHA1Signatures = clientAllow, serverAllow
				return cc, sc
			}
			for _, tc := range []struct{ client, server bool }{{false, false}, {true, false}, {false, true}} {
				cc, sc := cfgs(tc.client, tc.server)
				if _, _, err := xPair(t, cc, sc); err == nil {
					t.Fatalf("client %v server %v: SHA-1 handshake succeeded", tc.client, tc.server)
				}
			}
			cc, sc := cfgs(true, true)
			client, server, err := xPair(t, cc, sc)
			if err != nil {
				t.Fatalf("%v (server: %v)", err, server.Handshake())
			}
			if got := client.ConnectionState().testingOnlyPeerSignatureAlgorithm; got != scheme {
				t.Errorf("server signed with %v", got)
			}
			if !client.ConnectionState().Ext.SHA1Signature || !server.ConnectionState().Ext.SHA1Signature {
				t.Error("Ext.SHA1Signature not set")
			}
		})
	}

	t.Run("not used when something better is offered", func(t *testing.T) {
		cc, sc := xConfigs(t, p.rsa)
		cc.MaxVersion = VersionTLS12
		cc.Ext.AllowSHA1Signatures, sc.Ext.AllowSHA1Signatures = true, true
		client, server, err := xPair(t, cc, sc)
		if err != nil {
			t.Fatal(err)
		}
		if client.ConnectionState().Ext.SHA1Signature || server.ConnectionState().Ext.SHA1Signature {
			t.Error("SHA-1 used although both sides prefer SHA-256")
		}
	})

	t.Run("never in TLS 1.3", func(t *testing.T) {
		cc, sc := xConfigs(t, p.rsa)
		cc.MinVersion = VersionTLS13
		cc.Ext.SignatureSchemes = []SignatureScheme{PKCS1WithSHA1}
		cc.Ext.AllowSHA1Signatures, sc.Ext.AllowSHA1Signatures = true, true
		if _, _, err := xPair(t, cc, sc); err == nil {
			t.Fatal("TLS 1.3 handshake with only SHA-1 offered succeeded")
		}
	})
}

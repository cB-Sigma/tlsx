// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"

	"golang.org/x/crypto/cryptobyte"
)

// Resumption of TLS 1.2 PSK sessions (PSKConfig.Resumption), by session
// ticket or session ID. A session of a PSK handshake is bound to its
// external PSK: its SessionState carries, in Extra, the identity, the
// server's hint and a fingerprint of the key (HMAC-SHA256 keyed with the
// PSK, so the key itself is not in the session). Before a session is
// resumed, each side looks the key up again, the server with Lookup and
// the client with Identity and Key or ClientKey, and resumes only if the
// identity still has a key with that fingerprint: removing or changing a
// key ends the resumption of its sessions.

// pskBindingTag starts tlsx's entry in SessionState.Extra.
const pskBindingTag = "tlsx-psk-session\x00"

type pskBinding struct {
	identity, hint []byte
	fingerprint    []byte
}

func pskFingerprint(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("tlsx PSK session binding"))
	return m.Sum(nil)
}

func (b *pskBinding) marshal() []byte {
	var c cryptobyte.Builder
	c.AddBytes([]byte(pskBindingTag))
	c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.identity) })
	c.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.hint) })
	c.AddUint8LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(b.fingerprint) })
	return c.BytesOrPanic()
}

// sessionPSKBinding finds the binding in a session's Extra.
func sessionPSKBinding(s *SessionState) (*pskBinding, bool) {
	for _, e := range s.Extra {
		if !bytes.HasPrefix(e, []byte(pskBindingTag)) {
			continue
		}
		in := cryptobyte.String(e[len(pskBindingTag):])
		b := &pskBinding{}
		var id, hint, fp cryptobyte.String
		if !in.ReadUint16LengthPrefixed(&id) || !in.ReadUint16LengthPrefixed(&hint) ||
			!in.ReadUint8LengthPrefixed(&fp) || !in.Empty() || len(fp) != sha256.Size {
			return nil, false
		}
		b.identity, b.hint, b.fingerprint = append([]byte{}, id...), append([]byte{}, hint...), append([]byte{}, fp...)
		return b, true
	}
	return nil, false
}

// bindPSK records a full PSK handshake's binding when the Config allows
// resumption (sessions of other PSK handshakes are not cached).
func (x *connExt) bindPSK(p *PSKConfig, identity, hint, key []byte) {
	x.pskBinding = nil
	if p != nil && p.Resumption {
		x.pskBinding = &pskBinding{identity: append([]byte{}, identity...), hint: append([]byte{}, hint...), fingerprint: pskFingerprint(key)}
	}
}

// sessionStateX adds the PSK binding to the SessionState of a PSK
// handshake.
func (x *connExt) sessionStateX(s *SessionState) *SessionState {
	if x.pskBinding != nil {
		s.Extra = append(s.Extra, x.pskBinding.marshal())
	}
	return s
}

// checkPSKSessionX is a TLS 1.2 server's check of a session it is asked to
// resume: a session of a PSK suite needs its binding, resumption allowed,
// and the identity's current key to match. It reports whether the
// session may be resumed.
func (hs *serverHandshakeState) checkPSKSessionX(s *SessionState) bool {
	c := hs.c
	b, bound := sessionPSKBinding(s)
	if !bound {
		return !IsPSKSuite(s.cipherSuite)
	}
	p := c.config.Ext.PSK
	if !p.serverReady() || !p.Resumption || !IsPSKSuite(s.cipherSuite) {
		return false
	}
	key, err := p.Lookup(hs.ctx, b.identity)
	if err != nil || len(key) == 0 || !hmac.Equal(pskFingerprint(key), b.fingerprint) {
		return false
	}
	c.x.pskIdentity = b.identity
	c.x.pskBinding = b
	return true
}

// Adapted from Go's crypto/tls/handshake_client.go: loadSession (the TLS
// 1.2 steps after the certificate checks, which a PSK session skips).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// loadPSKSessionX offers a cached TLS 1.2 PSK session if resumption is
// allowed and the identity still has the key the session was made with.
func (c *Conn) loadPSKSessionX(hello *clientHelloMsg, cacheKey string, cs *ClientSessionState, b *pskBinding) *SessionState {
	session := cs.session
	p := c.config.Ext.PSK
	if session.version == VersionTLS13 || p == nil || !p.Resumption || !IsPSKSuite(session.cipherSuite) {
		return nil
	}
	identity, key := p.Identity, p.Key
	if p.ClientKey != nil {
		var err error
		if identity, key, err = p.ClientKey(append([]byte{}, b.hint...)); err != nil {
			return nil
		}
	}
	if !bytes.Equal(identity, b.identity) || len(key) == 0 || !hmac.Equal(pskFingerprint(key), b.fingerprint) {
		c.config.ClientSessionCache.Put(cacheKey, nil) // the key is gone or changed
		return nil
	}
	if mutualCipherSuite(hello.cipherSuites, session.cipherSuite) == nil {
		return nil
	}
	hello.sessionTicket = session.ticket
	if session.ticket == nil && cs.sessionID != nil {
		hello.sessionId = cs.sessionID
	}
	return session
}

// resumedPSKX restores a resumed PSK session's identity on a client.
func (x *connExt) resumedPSKX(s *SessionState) {
	if b, ok := sessionPSKBinding(s); ok {
		x.pskIdentity, x.pskHint, x.pskBinding = b.identity, b.hint, b
	}
}

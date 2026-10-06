// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"hash"
	"slices"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/tls13"
)

// Resumption of TLS 1.3 sessions made with an external PSK
// (PSKConfig.Resumption with PSKConfig.TLS13; RFC 8446 2.2, 4.6.1).
//
// After an external-PSK handshake the server sends a NewSessionTicket as
// for any TLS 1.3 handshake, and the client resumes with the resumption
// PSK of that ticket. The session is bound to its external PSK as TLS 1.2
// PSK sessions are (x_psk_resume.go): the SessionState carries the
// identity and a fingerprint of the key in Extra, and before a session is
// resumed the client checks Identity and Key and the server calls Lookup.
// A removed or changed key ends the resumption of its sessions.
//
// The client offers the ticket first and, unless Encrypted Client Hello is
// used, the external identity second, each with its own binder (the
// resumption binder key for the ticket, the external one for the PSK), so a
// server that cannot resume the ticket can still use the external PSK
// without another round trip. The ticket's obfuscated_ticket_age is the
// ticket's age plus ticket_age_add; the external identity's is 0. A server
// tries the tickets before the external identities.
//
// psk_ke (no (EC)DHE) is used on resumption under the same rules as for
// the external PSK: offered by a client with AllowNoDHE, chosen by a server
// with AllowNoDHE when the client offers nothing else or PreferNoDHE is
// set. Sessions without a PSK binding (certificate handshakes) are
// resumed with psk_dhe_ke only, as upstream. QUIC connections neither
// use external PSKs nor resume their sessions.

// pskExtOffer is a TLS 1.3 client's external PSK offered after the ticket
// of one of its sessions.
type pskExtOffer struct {
	identity    []byte
	session     *SessionState // stands for the PSK, as loadExternalPSK's
	earlySecret *tls13.EarlySecret
	binderKey   []byte
}

// loadPSKSession13X is a TLS 1.3 client's check of a cached session bound
// to an external PSK: resumption allowed, and the configured identity
// still has the key the session was made with. A session of a removed or
// changed key is dropped from the cache.
func (c *Conn) loadPSKSession13X(cacheKey string, b *pskBinding) bool {
	p := c.config.Ext.PSK
	if p == nil || !p.TLS13 || !p.Resumption || c.quic != nil {
		return false
	}
	if !bytes.Equal(p.Identity, b.identity) || len(p.Key) == 0 || !hmac.Equal(pskFingerprint(p.Key), b.fingerprint) {
		c.config.ClientSessionCache.Put(cacheKey, nil)
		return false
	}
	return true
}

// offerPSKTicketX completes a ClientHello that offers the ticket of a
// session bound to an external PSK (pskIdentities[0], with its binder
// placeholder): psk_ke when allowed, the external identity second (not with
// ECH, whose outer hello carries no PSK and whose inner hello tlsx keeps
// free of external identities), and the binders.
func (c *Conn) offerPSKTicketX(hello *clientHelloMsg, session *SessionState, suite *cipherSuiteTLS13, binderKey []byte) error {
	if _, ok := sessionPSKBinding(session); !ok {
		return nil
	}
	p := c.config.Ext.PSK
	if p.AllowNoDHE && !slices.Contains(hello.pskModes, pskModePlain) {
		hello.pskModes = append(hello.pskModes, pskModePlain)
	}
	c.x.pskPlainOffered = slices.Contains(hello.pskModes, pskModePlain)
	extSuite := cipherSuiteTLS13ByID(tls13SuiteForHash(p.hash()))
	if len(hello.encryptedClientHello) == 0 && extSuite.hash == suite.hash && len(hello.pskIdentities) == 1 &&
		checkPSKLengths(p.Identity, p.Key, true) == nil {
		earlySecret := tls13.NewEarlySecret(suite.hash.New, p.Key)
		c.x.pskAlongside = &pskExtOffer{
			identity:    slices.Clone(p.Identity),
			session:     &SessionState{version: VersionTLS13, cipherSuite: extSuite.id, secret: p.Key, createdAt: uint64(c.config.time().Unix())},
			earlySecret: earlySecret,
			binderKey:   earlySecret.ExternalBinderKey(),
		}
		// RFC 8446 4.2.11: an external identity's obfuscated_ticket_age is 0.
		hello.pskIdentities = append(hello.pskIdentities, pskIdentity{label: slices.Clone(p.Identity)})
		hello.pskBinders = append(hello.pskBinders, make([]byte, suite.hash.Size()))
	}
	return c.x.updatePSKBindersX(hello, binderKey, suite.hash.New(), suite)
}

// Adapted from Go's crypto/tls/handshake_client.go: computeAndUpdatePSK
// (one binder per identity over the same partial ClientHello).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// updatePSKBindersX computes the binders of a ClientHello: the first with
// binderKey and, when an external PSK follows a ticket, the second with the
// external binder key. transcript holds what precedes the ClientHello.
func (x *connExt) updatePSKBindersX(m *clientHelloMsg, binderKey []byte, transcript hash.Hash, suite *cipherSuiteTLS13) error {
	if x.pskAlongside == nil || len(m.pskIdentities) != 2 {
		return computeAndUpdatePSK(m, binderKey, transcript, suite.finishedHash)
	}
	helloBytes, err := m.marshalWithoutBinders()
	if err != nil {
		return err
	}
	external := cloneHash(transcript, suite.hash)
	if external == nil {
		return errors.New("tls: internal error: failed to clone hash")
	}
	transcript.Write(helloBytes)
	external.Write(helloBytes)
	return m.updateBinders([][]byte{
		suite.finishedHash(binderKey, transcript),
		suite.finishedHash(x.pskAlongside.binderKey, external),
	})
}

// pickPSKX follows a TLS 1.3 server's choice between the ticket and the
// external PSK offered after it: the external PSK replaces the session.
func (hs *clientHandshakeStateTLS13) pickPSKX() {
	a := hs.c.x.pskAlongside
	if a == nil || len(hs.hello.pskIdentities) != 2 || hs.serverHello.selectedIdentity != 1 {
		return
	}
	hs.session, hs.earlySecret = a.session, a.earlySecret
	hs.c.x.pskOffered = a.identity
}

// pskPlainResumptionOK says a TLS 1.3 server may resume a session bound
// to an external PSK with psk_ke, the only mode the client offers.
func (hs *serverHandshakeStateTLS13) pskPlainResumptionOK() bool {
	p := hs.c.config.Ext.PSK
	return p.serverReady() && p.TLS13 && p.Resumption && p.AllowNoDHE && hs.c.quic == nil &&
		slices.Contains(hs.clientHello.pskModes, pskModePlain)
}

// checkPSKSession13X is a TLS 1.3 server's check of a session it is asked
// to resume. A session bound to an external PSK needs resumption allowed,
// a PSK mode we accept and the identity's current key to match; other
// sessions need psk_dhe_ke, as upstream.
func (hs *serverHandshakeStateTLS13) checkPSKSession13X(s *SessionState) bool {
	c := hs.c
	dhe := slices.Contains(hs.clientHello.pskModes, pskModeDHE)
	b, bound := sessionPSKBinding(s)
	if !bound {
		return dhe
	}
	p := c.config.Ext.PSK
	if !p.serverReady() || !p.TLS13 || !p.Resumption || c.quic != nil || !dhe && !hs.pskPlainResumptionOK() {
		return false
	}
	key, err := p.Lookup(hs.ctx, b.identity)
	return err == nil && len(key) > 0 && hmac.Equal(pskFingerprint(key), b.fingerprint)
}

// resumedPSKSession13X records a TLS 1.3 server's resumption of a session
// bound to an external PSK: its identity and binding, and psk_ke when that
// is the mode to use.
func (hs *serverHandshakeStateTLS13) resumedPSKSession13X(s *SessionState) {
	b, ok := sessionPSKBinding(s)
	if !ok {
		return
	}
	c := hs.c
	c.x.pskIdentity, c.x.pskBinding = b.identity, b
	hs.choosePSKModeX(c.config.Ext.PSK)
}

// choosePSKModeX switches a TLS 1.3 server's PSK handshake to psk_ke when
// the client offers only that, or offers both and PreferNoDHE is set: no
// key_share in the ServerHello, zeros as the (EC)DHE input.
func (hs *serverHandshakeStateTLS13) choosePSKModeX(p *PSKConfig) {
	dhe := slices.Contains(hs.clientHello.pskModes, pskModeDHE)
	plain := p.AllowNoDHE && slices.Contains(hs.clientHello.pskModes, pskModePlain)
	if !dhe || plain && p.PreferNoDHE {
		hs.sharedKey = nil
		hs.hello.serverShare = keyShare{}
		hs.c.curveID = 0
	}
}

// pskPlainTicketsX says a TLS 1.3 server sends tickets to a client that
// offered only psk_ke: for a session bound to an external PSK that it may
// resume with psk_ke.
func (hs *serverHandshakeStateTLS13) pskPlainTicketsX() bool {
	return hs.c.x.pskBinding != nil && hs.pskPlainResumptionOK()
}

// ticketsBeforeExternalPSK runs a TLS 1.3 server's ticket checks
// (upstream's checkForResumption) before its external identities, when
// sessions of external PSKs may be resumed. tried says they ran;
// hs.usingPSK then says a ticket was resumed.
func (hs *serverHandshakeStateTLS13) ticketsBeforeExternalPSK() (tried bool, err error) {
	c := hs.c
	if !c.config.Ext.PSK.Resumption || c.config.SessionTicketsDisabled {
		return false, nil
	}
	c.x.pskTicketPass = true
	err = hs.checkForResumption()
	c.x.pskTicketPass = false
	return true, err
}

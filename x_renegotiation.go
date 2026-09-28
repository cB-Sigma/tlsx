// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// TLS 1.2 renegotiation (RFC 5246 7.4.1, secure renegotiation of RFC 5746
// only), in both roles:
//
//   - a client starts one with Renegotiate (full handshake, certificates
//     validated again) or Resume (abbreviated: the session is resumed on
//     the connection for new keys) and answers a server's HelloRequest
//     when Config.Renegotiation allows;
//   - a server asks for one with RequestRenegotiation (HelloRequest) and
//     answers a client's ClientHello when it asked or
//     Config.Ext.AcceptRenegotiation is set.
//
// Renegotiation never changes the TLS version or the peer's leaf
// certificate, and is refused (the connection is aborted) with a peer
// that did not signal RFC 5746 in the first handshake. Application data
// the peer sends before its ChangeCipherSpec is kept and delivered by the
// next Read; our own writes wait until the renegotiation is over.

// Renegotiate runs a full TLS 1.2 renegotiation as client and returns when
// it completed. The server's certificate chain is validated again
// (Config.VerifyConnection runs). A server that refuses (no_renegotiation)
// leaves the connection as it was and ErrRenegotiationRefusedByPeer is
// returned.
func (c *Conn) Renegotiate() error { return c.RenegotiateContext(context.Background(), false) }

// Resume runs an abbreviated TLS 1.2 renegotiation as client: the current
// session (from Config.ClientSessionCache) is resumed on the connection,
// which gives new keys without a certificate exchange (the session
// renewal of IEC 62351-3 7.4.4). Without a cached session it is a full
// renegotiation.
func (c *Conn) Resume() error { return c.RenegotiateContext(context.Background(), true) }

// ErrRenegotiationRefusedByPeer: the server answered no_renegotiation.
var ErrRenegotiationRefusedByPeer = errors.New("tlsx: the server refused the renegotiation")

// RenegotiateContext is Renegotiate (resume false) or Resume (resume
// true); if ctx ends first the connection is closed.
func (c *Conn) RenegotiateContext(ctx context.Context, resume bool) (err error) {
	if err := c.Handshake(); err != nil {
		return err
	}
	if !c.isClient {
		return errors.New("tlsx: Renegotiate is for clients; a server uses RequestRenegotiation")
	}
	if c.vers > VersionTLS12 {
		return ErrNotTLS12
	}
	if c.quic != nil {
		return errors.New("tlsx: no renegotiation with QUIC")
	}
	if c.config.Renegotiation == RenegotiateNever {
		return ErrRenegotiationNotAllowed
	}
	if !c.secureRenegotiation {
		c.observe(Event{Kind: EventRenegotiationRefused, Err: ErrInsecureRenegotiation})
		return ErrInsecureRenegotiation
	}
	if ctx.Done() != nil {
		stop := context.AfterFunc(ctx, func() { _ = c.conn.Close() })
		defer func() {
			if !stop() && err == nil {
				err = ctx.Err()
			}
		}()
	}

	c.x.renegMu.Lock()
	defer c.x.renegMu.Unlock()
	c.x.renegGate.Lock()
	defer c.x.renegGate.Unlock()
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	if c.handshakeErr != nil {
		return c.handshakeErr
	}

	c.x.renegResume = resume
	c.x.peerRefused.Store(false)
	c.x.clientRenegPending.Store(true)
	var release func()
	c.x.acquireIn = func() error {
		if release == nil {
			release = c.x.lockIn(c)
			c.x.stashInput(c)
		}
		if c.x.peerRefused.Load() { // a reader saw no_renegotiation
			return errPeerRefusedRenegotiation
		}
		return nil
	}
	defer func() {
		c.x.acquireIn = nil
		c.x.clientRenegPending.Store(false)
		c.x.renegResume = false
		if release != nil { // nil: the ClientHello was never sent
			release()
		}
	}()
	return c.runRenegotiation(func() error { return c.clientHandshake(context.Background()) }, false)
}

// RequestRenegotiation sends a HelloRequest (TLS 1.2 server). The client
// answers with a ClientHello, which the connection processes as it is
// read; ConnectionState().Ext.Handshakes counts completed handshakes.
func (c *Conn) RequestRenegotiation() error {
	if err := c.Handshake(); err != nil {
		return err
	}
	if c.isClient {
		return errors.New("tlsx: RequestRenegotiation is for servers; a client uses Renegotiate")
	}
	if c.vers > VersionTLS12 {
		return ErrNotTLS12
	}
	if !c.x.peerSecureReneg {
		c.observe(Event{Kind: EventRenegotiationRefused, Err: ErrInsecureRenegotiation})
		return ErrInsecureRenegotiation
	}
	c.x.renegGate.RLock() // not while a renegotiation runs
	defer c.x.renegGate.RUnlock()
	c.out.Lock()
	defer c.out.Unlock()
	if c.out.err != nil {
		return c.out.err
	}
	b, err := (&helloRequestMsg{}).marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecordLocked(recordTypeHandshake, b); err != nil {
		return c.out.setErrorLocked(err)
	}
	c.x.helloRequested.Store(true)
	c.observe(Event{Kind: EventHelloRequestSent})
	return nil
}

// stashInput keeps unread application data before a renegotiation reads
// records (it would otherwise be overwritten).
func (x *connExt) stashInput(c *Conn) {
	if n := c.input.Len(); n > 0 {
		b := make([]byte, n)
		_, _ = io.ReadFull(&c.input, b)
		x.pendingApp = append(b, x.pendingApp...)
		c.input.Reset(nil)
	}
}

// deliverPending hands data received during a renegotiation to Read.
func (x *connExt) deliverPending(c *Conn) {
	if len(x.pendingApp) > 0 && c.input.Len() == 0 {
		c.input.Reset(x.pendingApp)
		x.pendingApp = nil
	}
}

// runRenegotiation runs handshake as a renegotiation; c.in (or the means
// to get it, acquireIn), handshakeMutex, renegMu and renegGate are held.
func (c *Conn) runRenegotiation(handshake func() error, byPeer bool) error {
	prevVers, prevResume, prevCurve, prevSuite := c.vers, c.didResume, c.curveID, c.cipherSuite
	c.x.prevLeaf = nil
	if len(c.peerCertificates) > 0 {
		c.x.prevLeaf = c.peerCertificates[0].Raw
	}
	c.x.renegotiating = true
	c.isHandshakeComplete.Store(false)
	c.observe(Event{Kind: EventRenegotiationStarted, ByPeer: byPeer})
	err := handshake()
	c.x.renegotiating = false
	defer c.x.deliverPending(c)

	if errors.Is(err, errPeerRefusedRenegotiation) {
		// The server ignored our ClientHello; nothing changed.
		c.x.peerRefused.Store(false)
		c.vers, c.didResume, c.curveID, c.cipherSuite = prevVers, prevResume, prevCurve, prevSuite
		c.isHandshakeComplete.Store(true)
		c.observe(Event{Kind: EventRenegotiationRefused, Err: ErrRenegotiationRefusedByPeer})
		return ErrRenegotiationRefusedByPeer
	}
	if err != nil {
		c.handshakeErr = err
		c.flush()
		var vc *versionChangeError
		if errors.As(err, &vc) {
			c.observe(Event{Kind: EventRenegotiationRefused, Err: ErrRenegotiationVersionChange, PeerVersion: vc.peer})
		} else {
			c.observe(Event{Kind: EventRenegotiationFailed, Err: err})
		}
		return err
	}
	c.handshakes++
	c.observe(Event{Kind: EventRenegotiated, ByPeer: byPeer, Resumed: c.didResume})
	return nil
}

// versionChangeError is a renegotiation that asked for another version.
type versionChangeError struct{ have, peer uint16 }

func (e *versionChangeError) Error() string {
	return fmt.Sprintf("tlsx: renegotiation asked for %s on a %s connection", VersionName(e.peer), VersionName(e.have))
}

func (e *versionChangeError) Unwrap() error { return ErrRenegotiationVersionChange }

// handleRenegotiationX replaces upstream's handleRenegotiation: it runs on
// the reading goroutine (c.in held) when a TLS 1.2 handshake message
// arrives after the handshake: a HelloRequest (client) or a ClientHello
// (server).
func (c *Conn) handleRenegotiationX() error {
	if c.vers == VersionTLS13 {
		return errors.New("tls: internal error: unexpected renegotiation")
	}
	// A renegotiation started through the API is running or about to wait
	// for c.in: let it have the message.
	for !c.x.renegMu.TryLock() {
		if c.x.yieldIn(c) {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
	defer c.x.renegMu.Unlock()
	if c.isClient {
		return c.handleHelloRequest()
	}
	return c.handlePeerRenegotiation()
}

// handleHelloRequest is adapted from Go's (*Conn).handleRenegotiation in
// src/crypto/tls/conn.go (Copyright 2010 The Go Authors; see NOTICE): the
// HelloRequest checks and the Config.Renegotiation policy are Go's, with
// tlsx's events and RFC 5746 requirement added.
func (c *Conn) handleHelloRequest() error {
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}
	switch c.config.Renegotiation {
	case RenegotiateNever:
		c.observe(Event{Kind: EventRenegotiationRefused, ByPeer: true, Err: ErrRenegotiationNotAllowed})
		return c.sendAlert(alertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			c.observe(Event{Kind: EventRenegotiationRefused, ByPeer: true, Err: ErrRenegotiationNotAllowed})
			return c.sendAlert(alertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
	default:
		c.sendAlert(alertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}
	if !c.secureRenegotiation {
		// IEC 62351-3 7.5.2: no renegotiation without RFC 5746.
		c.observe(Event{Kind: EventRenegotiationRefused, ByPeer: true, Err: ErrInsecureRenegotiation})
		c.sendAlert(alertHandshakeFailure)
		return c.in.setErrorLocked(ErrInsecureRenegotiation)
	}
	c.x.renegGate.Lock()
	defer c.x.renegGate.Unlock()
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	c.x.stashInput(c)
	return c.runRenegotiation(func() error { return c.clientHandshake(context.Background()) }, true)
}

// handlePeerRenegotiation answers a client's renegotiation ClientHello.
func (c *Conn) handlePeerRenegotiation() error {
	if b := c.hand.Bytes(); len(b) == 0 || b[0] != typeClientHello {
		c.sendAlert(alertUnexpectedMessage)
		return c.in.setErrorLocked(errors.New("tls: unexpected handshake message after the handshake"))
	}
	if !c.x.peerSecureReneg {
		c.observe(Event{Kind: EventRenegotiationRefused, ByPeer: true, Err: ErrInsecureRenegotiation})
		c.sendAlert(alertHandshakeFailure)
		return c.in.setErrorLocked(ErrInsecureRenegotiation)
	}
	requested := c.x.helloRequested.Swap(false)
	if !requested && !c.config.Ext.AcceptRenegotiation {
		// Read and drop the ClientHello; the connection goes on.
		if _, err := c.readHandshake(nil); err != nil {
			return err
		}
		c.observe(Event{Kind: EventRenegotiationRefused, ByPeer: true, Err: ErrRenegotiationNotAllowed})
		c.out.Lock()
		defer c.out.Unlock()
		c.tmp[0], c.tmp[1] = alertLevelWarning, byte(alertNoRenegotiation)
		if _, err := c.writeRecordLocked(recordTypeAlert, c.tmp[:2]); err != nil {
			return c.out.setErrorLocked(err)
		}
		return nil
	}
	c.x.renegGate.Lock()
	defer c.x.renegGate.Unlock()
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()
	c.x.stashInput(c)
	return c.runRenegotiation(func() error { return c.serverHandshake(context.Background()) }, !requested)
}

// ---- hooks called from the upstream handshake code ------------------------

// renegotiationClientHello restricts a client renegotiation's versions to
// the connection's.
func (c *Conn) renegotiationVersions(v []uint16) []uint16 {
	if c.handshakes > 0 && c.vers != 0 {
		return []uint16{c.vers}
	}
	return v
}

// checkRenegotiationVersion refuses a renegotiation that negotiates
// another version (server: from the ClientHello; client: ServerHello).
func (c *Conn) checkRenegotiationVersion(prev, got uint16) error {
	if c.handshakes > 0 && prev != 0 && prev != got {
		c.vers = prev
		c.sendAlert(alertProtocolVersion)
		return &versionChangeError{have: prev, peer: got}
	}
	return nil
}

// checkRenegotiationIdentity refuses a renegotiation in which the peer's
// leaf certificate changed (see https://mitls.org/pages/attacks/3SHAKE).
func (c *Conn) checkRenegotiationIdentity(leaf []byte) error {
	if c.handshakes > 0 && c.x.prevLeaf != nil && !bytes.Equal(c.x.prevLeaf, leaf) {
		c.sendAlert(alertBadCertificate)
		return errors.New("tls: peer's identity changed during renegotiation")
	}
	return nil
}

// checkNoExcessHandshakeX refuses handshake data that came in the same
// record as the server's Finished (TLS 1.2 client). crypto/tls leaves it
// buffered until the next record arrives, so a HelloRequest packed with
// the Finished stalled the client while the server waited for its
// ClientHello. tlsx refuses it at once with unexpected_message, as
// BoringSSL does (BoGo's Renegotiate-Client-Packed); TLS 1.3 already
// refuses buffered handshake data at each change of keys.
func (c *Conn) checkNoExcessHandshakeX() error {
	if c.hand.Len() > 0 {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("tlsx: handshake data after the server's Finished in the same record")
	}
	return nil
}

// renegotiationEMSError is the refusal of a renegotiation that changes the
// use of the extended master secret (RFC 7627): had is the connection's,
// got the new handshake's. Dropping it would leave the renegotiated
// session without the protection the connection had (and ConnectionState
// would still report it); taking it up mid-connection is refused too, as
// BoringSSL does.
func renegotiationEMSError(handshakes int, had, got bool) error {
	if handshakes > 0 && had != got {
		return errors.New("tlsx: renegotiation changed the use of the extended master secret")
	}
	return nil
}

// checkRenegotiationEMS applies renegotiationEMSError to a handshake.
func (c *Conn) checkRenegotiationEMS(got bool) error {
	if err := renegotiationEMSError(c.handshakes, c.extMasterSecret, got); err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	return nil
}

// serverRenegotiationInfo checks a server-side ClientHello's
// renegotiation_info and returns the ServerHello's.
func (c *Conn) serverRenegotiationInfo(ch *clientHelloMsg) ([]byte, error) {
	if c.handshakes == 0 {
		if len(ch.secureRenegotiation) != 0 {
			c.sendAlert(alertHandshakeFailure)
			return nil, errors.New("tls: initial handshake had non-empty renegotiation extension")
		}
		c.x.peerSecureReneg = ch.secureRenegotiationSupported
		return nil, nil
	}
	if !bytes.Equal(ch.secureRenegotiation, c.clientFinished[:]) {
		c.sendAlert(alertHandshakeFailure)
		return nil, fmt.Errorf("%w: wrong client_verify_data in renegotiation_info", ErrInsecureRenegotiation)
	}
	info := make([]byte, 0, 24)
	info = append(info, c.clientFinished[:]...)
	return append(info, c.serverFinished[:]...), nil
}

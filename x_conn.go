// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// connExt is the per-connection state tlsx adds to Conn.
type connExt struct {
	// sha1Sig: a SHA-1 signature was made or verified (StateExt).
	sha1Sig bool

	// renegGate: Write holds it shared; a renegotiation holds it
	// exclusively, so no application data is written while the handshake
	// messages and the change of keys go out.
	renegGate sync.RWMutex
	// renegMu serialises renegotiations (API calls and peer requests).
	renegMu sync.Mutex
	// inWait, when set, is a renegotiation on another goroutine waiting
	// for c.in; a reader holding c.in hands it over and waits for the
	// channel to close.
	inWaitMu sync.Mutex
	inWait   chan struct{}
	// renegotiating is set while a renegotiation handshake runs (c.in
	// held): application data then goes to pendingApp.
	renegotiating bool
	pendingApp    []byte
	// clientRenegPending is set while a client renegotiation waits for the
	// server's answer; peerRefused records a no_renegotiation warning.
	clientRenegPending atomic.Bool
	peerRefused        atomic.Bool
	// renegResume offers the session in a client renegotiation.
	renegResume bool
	// acquireIn, set during a client renegotiation started through the
	// API, takes c.in once the ClientHello is out.
	acquireIn func() error
	// helloRequested: the server sent HelloRequest and waits.
	helloRequested atomic.Bool
	// peerSecureReneg: the peer signalled RFC 5746 in the first handshake
	// (server side; the client side is Conn.secureRenegotiation).
	peerSecureReneg bool
	// prevLeaf is the peer's leaf certificate of the previous handshake
	// (a renegotiation may not change the peer's identity).
	prevLeaf []byte

	keyUpdatesSent, keyUpdatesReceived atomic.Uint64
	lastKeyUpdate                      atomic.Int64 // unix nanoseconds

	maxFragment    int       // record plaintext limit (max_fragment_length), 0 none
	sessionCreated time.Time // server, TLS 1.2 resumption: the session's full handshake
	ocspResponses  [][]byte
	trustedCAAck   bool
	peerCAs        [][]byte
	peerAttrCerts  [][]byte // RFC 5878

	pskIdentity, pskHint  []byte      // the PSK identity used, a TLS 1.2 client's hint
	pskOffered            []byte      // TLS 1.3 client: the external identity offered
	pskBinding            *pskBinding // a resumable TLS 1.2 PSK session's binding (x_psk_resume.go)
	peerRawKey, ownRawKey bool        // RFC 7250 raw public key negotiated per side
	peerRawKeySPKI        []byte
}

var errPeerRefusedRenegotiation = errors.New("tlsx: peer refused the renegotiation (no_renegotiation)")

// noteNoRenegotiation records a no_renegotiation warning; it reports
// whether a client renegotiation was waiting for it.
func (x *connExt) noteNoRenegotiation() bool {
	if !x.clientRenegPending.Load() {
		return false
	}
	x.peerRefused.Store(true)
	return true
}

// yieldIn hands c.in (held by the caller, a reader) to a renegotiation
// waiting for it and takes it back once that is done. It reports whether
// it did.
func (x *connExt) yieldIn(c *Conn) bool {
	x.inWaitMu.Lock()
	ch := x.inWait
	x.inWaitMu.Unlock()
	if ch == nil {
		return false
	}
	c.in.Unlock()
	<-ch
	c.in.Lock()
	return true
}

// lockIn takes c.in for a renegotiation running outside Read: a reader
// blocked in Read hands it over when the next record arrives. release
// gives it back.
func (x *connExt) lockIn(c *Conn) (release func()) {
	ch := make(chan struct{})
	x.inWaitMu.Lock()
	x.inWait = ch
	x.inWaitMu.Unlock()
	c.in.Lock()
	x.inWaitMu.Lock()
	x.inWait = nil
	x.inWaitMu.Unlock()
	return func() {
		c.in.Unlock()
		close(ch)
	}
}

func (x *connExt) keyUpdateSent(c *Conn, requested bool) {
	x.keyUpdatesSent.Add(1)
	c.observe(Event{Kind: EventKeyUpdateSent, Requested: requested})
}

func (x *connExt) keyUpdateReceived(c *Conn, requested bool) {
	x.keyUpdatesReceived.Add(1)
	x.lastKeyUpdate.Store(c.config.time().UnixNano())
	c.observe(Event{Kind: EventKeyUpdateReceived, Requested: requested, ByPeer: true})
}

func (x *connExt) state(c *Conn, s *ConnectionState) {
	s.Ext.EncryptThenMAC = c.out.etm || c.in.etm
	s.Ext.MaxFragmentLength = x.maxFragment
	if c.isClient {
		s.Ext.SecureRenegotiation = c.secureRenegotiation
	} else {
		s.Ext.SecureRenegotiation = x.peerSecureReneg
	}
	s.Ext.Handshakes = c.handshakes
	s.Ext.SHA1Signature = x.sha1Sig
	s.Ext.KeyUpdatesSent = x.keyUpdatesSent.Load()
	s.Ext.KeyUpdatesReceived = x.keyUpdatesReceived.Load()
	if t := x.lastKeyUpdate.Load(); t != 0 {
		s.Ext.LastKeyUpdateReceived = time.Unix(0, t)
	}
	s.Ext.OCSPResponses = x.ocspResponses
	if len(s.Ext.OCSPResponses) == 0 && len(c.ocspResponse) > 0 {
		s.Ext.OCSPResponses = [][]byte{c.ocspResponse}
	}
	s.Ext.TrustedCAKeysAcknowledged = x.trustedCAAck
	if c.didResume {
		s.Ext.SessionCreated = x.sessionCreated
	}
	s.Ext.PeerCertificateAuthorities = x.peerCAs
	s.Ext.PeerAttributeCertificates = x.peerAttrCerts
	s.Ext.PSKIdentity, s.Ext.PSKIdentityHint = x.pskIdentity, x.pskHint
	s.Ext.OwnRawPublicKey = x.ownRawKey
	if x.peerRawKey && x.peerRawKeySPKI != nil {
		s.PeerCertificates = nil
		s.Ext.PeerRawPublicKey = x.peerRawKeySPKI
	}
}

// SendKeyUpdate sends a TLS 1.3 KeyUpdate and switches to new sending keys
// (RFC 8446 4.6.3). With requestPeerUpdate the peer is asked to update its
// sending keys too; its KeyUpdate is processed as the connection is read
// (ConnectionState().Ext.KeyUpdatesReceived, EventKeyUpdateReceived).
//
// Since Go 1.26.6 a KeyUpdate no longer counts as progress on a connection:
// a tlsx or crypto/tls peer closes the connection ("too many non-advancing
// records") after more than 16 post-handshake messages in a row with no
// application data between them. Callers that update keys on a timer
// should make sure some data flows between updates.
func (c *Conn) SendKeyUpdate(requestPeerUpdate bool) error {
	if err := c.Handshake(); err != nil {
		return err
	}
	if c.vers != VersionTLS13 {
		return ErrNotTLS13
	}
	if c.quic != nil {
		return errors.New("tlsx: KeyUpdate is not used with QUIC")
	}
	suite := cipherSuiteTLS13ByID(c.cipherSuite)
	if suite == nil {
		return errors.New("tlsx: internal error: no TLS 1.3 cipher suite")
	}
	c.out.Lock()
	defer c.out.Unlock()
	if c.out.err != nil {
		return c.out.err
	}
	if c.closeNotifySent {
		return errShutdown
	}
	// Adapted from Go's crypto/tls/conn.go: handleKeyUpdate (the send half:
	// marshal, writeRecordLocked, setWriteTrafficSecret).
	// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
	b, err := (&keyUpdateMsg{updateRequested: requestPeerUpdate}).marshal()
	if err != nil {
		return err
	}
	if _, err := c.writeRecordLocked(recordTypeHandshake, b); err != nil {
		return c.out.setErrorLocked(err)
	}
	c.setWriteTrafficSecret(suite, QUICEncryptionLevelInitial, suite.nextTrafficSecret(c.out.trafficSecret))
	c.x.keyUpdateSent(c, requestPeerUpdate)
	return nil
}

// ---- encrypt_then_mac (RFC 7366) ----------------------------------------

// encryptEtM appends the CBC encryption of payload (explicit IV already in
// record) and the MAC over the header, IV and ciphertext.
func (hc *halfConn) encryptEtM(c cbcMode, record, payload, explicitIV []byte) []byte {
	blockSize := c.BlockSize()
	paddingLen := blockSize - len(payload)%blockSize
	var dst []byte
	record, dst = sliceForAppend(record, len(payload)+paddingLen)
	copy(dst, payload)
	for i := len(payload); i < len(dst); i++ {
		dst[i] = byte(paddingLen - 1)
	}
	if len(explicitIV) > 0 {
		c.SetIV(explicitIV)
	}
	c.CryptBlocks(dst, dst)
	n := len(record) - recordHeaderLen
	record[3], record[4] = byte(n>>8), byte(n)
	mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], record[recordHeaderLen:], nil)
	return append(record, mac...)
}

// decryptEtM checks the MAC over the header, IV and ciphertext, then
// decrypts and removes the padding.
func (hc *halfConn) decryptEtM(c cbcMode, record, payload []byte, ivLen int) ([]byte, error) {
	blockSize := c.BlockSize()
	macSize := hc.mac.Size()
	if len(payload) < ivLen+blockSize+macSize || (len(payload)-macSize-ivLen)%blockSize != 0 {
		return nil, alertBadRecordMAC
	}
	body := payload[:len(payload)-macSize]
	remote := payload[len(payload)-macSize:]
	var hdr [recordHeaderLen]byte
	copy(hdr[:], record[:recordHeaderLen])
	hdr[3], hdr[4] = byte(len(body)>>8), byte(len(body))
	local := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], hdr[:], body, nil)
	if !hmac.Equal(local, remote) {
		return nil, alertBadRecordMAC
	}
	if ivLen > 0 {
		c.SetIV(body[:ivLen])
	}
	ct := body[ivLen:]
	c.CryptBlocks(ct, ct)
	pad := int(ct[len(ct)-1])
	if pad+1 > len(ct) {
		return nil, alertBadRecordMAC
	}
	// The record is authenticated: the padding check need not be
	// constant time, but costs nothing to keep so.
	good := 1
	for _, b := range ct[len(ct)-pad-1:] {
		good &= subtle.ConstantTimeByteEq(b, byte(pad))
	}
	if good != 1 {
		return nil, alertBadRecordMAC
	}
	return ct[:len(ct)-pad-1], nil
}

// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"net/http"
	"os"
	"sync"
	"time"
)

// Extension identifiers of RFC 5280 (published values).
var (
	oidAuthorityKeyID    = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidCRLNumber         = asn1.ObjectIdentifier{2, 5, 29, 20}
	oidDeltaCRLIndicator = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistPoint  = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidEntryReasonCode   = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidEntryInvalidity   = asn1.ObjectIdentifier{2, 5, 29, 24}
	oidEntryCertIssuer   = asn1.ObjectIdentifier{2, 5, 29, 29}
	oidFreshestCRL       = asn1.ObjectIdentifier{2, 5, 29, 46}
	oidAuthorityInfoAcc  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidIssuerAltName     = asn1.ObjectIdentifier{2, 5, 29, 18}
	knownCRLExtensions   = []asn1.ObjectIdentifier{oidAuthorityKeyID, oidCRLNumber, oidFreshestCRL, oidAuthorityInfoAcc, oidIssuerAltName}
)

// crl is a verified CRL as a source holds it. It is not modified after
// parseCRL returns, so checks read it without a lock.
type crl struct {
	number                 *big.Int // nil if the CRL has none
	thisUpdate, nextUpdate time.Time
	revoked                map[string]*revokedEntry
	scope                  scope
}

type revokedEntry struct {
	at     time.Time
	reason int
}

func serialKey(n *big.Int) string { return n.Text(16) }

type source struct {
	c        *Checker
	name     string
	location string
	isURL    bool
	issuer   *x509.Certificate
	policy   Policy

	refreshMu sync.Mutex // serialises refreshes of this source

	mu          sync.RWMutex
	crl         *crl
	lastAttempt time.Time
	lastSuccess time.Time
	lastErr     error
	backoff     int // consecutive refreshes without progress
	nextRefresh time.Time
}

func newSource(c *Checker, s Source) *source {
	src := &source{c: c, name: s.Name, issuer: s.Issuer, policy: s.Policy}
	if src.name == "" {
		src.name = s.Issuer.Subject.String()
	}
	if s.URL != "" {
		src.location, src.isURL = s.URL, true
	} else {
		src.location = s.File
	}
	return src
}

func (s *source) current() (*crl, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.crl, s.lastErr
}

func (s *source) status(now time.Time) SourceStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := SourceStatus{
		Name:        s.name,
		Location:    s.location,
		Issuer:      s.issuer.Subject.String(),
		Policy:      s.policy,
		State:       StateMissing,
		LastFetch:   s.lastAttempt,
		LastSuccess: s.lastSuccess,
		NextRefresh: s.nextRefresh,
	}
	if s.lastErr != nil {
		st.LastError = s.lastErr.Error()
	}
	if l := s.crl; l != nil {
		st.ThisUpdate, st.NextUpdate = l.thisUpdate, l.nextUpdate
		if l.number != nil {
			st.Number = new(big.Int).Set(l.number)
		}
		st.Revoked = len(l.revoked)
		st.State = StateOK
		if now.After(l.nextUpdate.Add(s.c.cfg.ClockSkew)) {
			st.State, st.Stale = StateStale, true
		}
	}
	return st
}

// run refreshes the source in the background until ctx is cancelled.
func (s *source) run(ctx context.Context) {
	defer s.c.wg.Done()
	for {
		s.mu.RLock()
		d := s.nextRefresh.Sub(s.c.cfg.Now())
		s.mu.RUnlock()
		if d > 0 {
			// Up to 10% jitter spreads the refreshes of many sources.
			d += rand.N(d/10 + 1)
		} else {
			d = 0
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		s.refresh(ctx)
	}
}

// refresh fetches, verifies and installs the source's CRL, and schedules
// the next refresh.
func (s *source) refresh(ctx context.Context) error {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	cfg := &s.c.cfg

	fctx, cancel := context.WithTimeout(ctx, cfg.FetchTimeout)
	data, err := s.fetch(fctx)
	cancel()
	now := cfg.Now()
	var l *crl
	if err == nil {
		l, err = s.parseCRL(data, now)
	}

	s.mu.Lock()
	s.lastAttempt = now
	kind := EventLoaded
	if err == nil {
		kind, err = s.accept(l, now)
	}
	if err != nil {
		err = fmt.Errorf("CRL %q from %s: %w", s.name, s.location, err)
		s.lastErr = err
		s.backoff++
	}
	s.nextRefresh = nextRefresh(now, s.crl, s.backoff, cfg)
	var number *big.Int
	if s.crl != nil && s.crl.number != nil {
		number = new(big.Int).Set(s.crl.number)
	}
	s.mu.Unlock()

	if err != nil {
		s.c.emit(Event{Kind: EventRefreshFailed, Source: s.name, Time: now, Err: err})
		return err
	}
	s.c.emit(Event{Kind: kind, Source: s.name, Time: now, Number: number})
	return nil
}

// accept installs l unless it would take the source back to an older CRL.
// It is called with s.mu held.
func (s *source) accept(l *crl, now time.Time) (EventKind, error) {
	cur := s.crl
	if cur != nil {
		switch {
		case cur.number != nil && l.number == nil:
			return 0, fmt.Errorf("refused: the new CRL has no CRL number and the current one has %s", cur.number)
		case cur.number != nil && l.number.Cmp(cur.number) < 0:
			return 0, fmt.Errorf("refused rollback: CRL number %s is lower than the current %s", l.number, cur.number)
		case cur.number != nil && l.number.Cmp(cur.number) == 0,
			cur.number == nil && l.number == nil && l.thisUpdate.Equal(cur.thisUpdate):
			// The same CRL again: nothing to install.
			s.lastSuccess, s.lastErr = now, nil
			if now.Before(cur.nextUpdate.Add(-s.c.cfg.RefreshMargin)) {
				s.backoff = 0
			} else {
				// Within the margin and the issuer has not published
				// a newer CRL yet: back off rather than poll.
				s.backoff++
			}
			return EventUnchanged, nil
		case cur.number == nil && l.number == nil && l.thisUpdate.Before(cur.thisUpdate):
			return 0, fmt.Errorf("refused rollback: thisUpdate %s is older than the current %s",
				l.thisUpdate.UTC().Format(time.RFC3339), cur.thisUpdate.UTC().Format(time.RFC3339))
		}
	}
	s.crl = l
	s.lastSuccess, s.lastErr, s.backoff = now, nil, 0
	return EventLoaded, nil
}

// nextRefresh schedules the next refresh: after RefreshInterval, or
// RefreshMargin before the CRL's nextUpdate if that is sooner, or after a
// back-off doubling from RetryMin to RetryMax when refreshes make no
// progress.
func nextRefresh(now time.Time, l *crl, backoff int, cfg *Config) time.Time {
	if backoff > 0 {
		d := cfg.RetryMin
		for i := 1; i < backoff && d < cfg.RetryMax; i++ {
			d *= 2
		}
		return now.Add(min(d, cfg.RetryMax))
	}
	next := now.Add(cfg.RefreshInterval)
	if l != nil {
		if t := l.nextUpdate.Add(-cfg.RefreshMargin); t.Before(next) {
			next = t
		}
	}
	if earliest := now.Add(cfg.RetryMin); next.Before(earliest) {
		next = earliest
	}
	return next
}

func (s *source) fetch(ctx context.Context) ([]byte, error) {
	max := s.c.cfg.MaxCRLSize
	if !s.isURL {
		f, err := os.Open(s.location)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return readLimited(f, max)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.location, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.c.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %s", resp.Status)
	}
	if resp.ContentLength > max {
		return nil, fmt.Errorf("CRL of %d bytes exceeds the limit of %d bytes", resp.ContentLength, max)
	}
	return readLimited(resp.Body, max)
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("CRL exceeds the limit of %d bytes", max)
	}
	return b, nil
}

// parseCRL decodes data (DER or PEM) and checks it against the source's
// issuer: issuer name, signature, extensions and times.
func (s *source) parseCRL(data []byte, now time.Time) (*crl, error) {
	der := data
	if bytes.HasPrefix(bytes.TrimSpace(data), []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "X509 CRL" {
			return nil, errors.New("PEM data holds no X509 CRL block")
		}
		der = block.Bytes
	}
	rl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(rl.RawIssuer, s.issuer.RawSubject) {
		return nil, fmt.Errorf("CRL issuer %q is not the CA %q", rl.Issuer, s.issuer.Subject)
	}
	if len(rl.AuthorityKeyId) > 0 && len(s.issuer.SubjectKeyId) > 0 &&
		!bytes.Equal(rl.AuthorityKeyId, s.issuer.SubjectKeyId) {
		return nil, errors.New("CRL authority key identifier does not match the CA's subject key identifier")
	}
	if err := rl.CheckSignatureFrom(s.issuer); err != nil {
		return nil, fmt.Errorf("CRL signature does not verify with the CA %q: %w", s.issuer.Subject, err)
	}

	l := &crl{number: rl.Number, thisUpdate: rl.ThisUpdate, nextUpdate: rl.NextUpdate}
	for _, e := range rl.Extensions {
		switch {
		case e.Id.Equal(oidDeltaCRLIndicator):
			return nil, errors.New("delta CRLs are not supported")
		case e.Id.Equal(oidIssuingDistPoint):
			if l.scope, err = parseIDP(e.Value); err != nil {
				return nil, err
			}
		case e.Critical && !oidIn(e.Id, knownCRLExtensions):
			return nil, fmt.Errorf("unsupported critical CRL extension %s", e.Id)
		}
	}
	if rl.NextUpdate.IsZero() {
		return nil, errors.New("CRL has no nextUpdate")
	}
	if !rl.NextUpdate.After(rl.ThisUpdate) {
		return nil, errors.New("CRL nextUpdate is not after its thisUpdate")
	}
	if rl.ThisUpdate.After(now.Add(s.c.cfg.ClockSkew)) {
		return nil, fmt.Errorf("CRL thisUpdate %s is in the future", rl.ThisUpdate.UTC().Format(time.RFC3339))
	}
	// A CRL already past its nextUpdate is kept: its entries still count,
	// and checks treat it as stale.

	l.revoked = make(map[string]*revokedEntry, len(rl.RevokedCertificateEntries))
	for _, e := range rl.RevokedCertificateEntries {
		for _, x := range e.Extensions {
			switch {
			case x.Id.Equal(oidEntryCertIssuer):
				return nil, errors.New("indirect CRLs (certificate issuer entry extension) are not supported")
			case x.Critical && !x.Id.Equal(oidEntryReasonCode) && !x.Id.Equal(oidEntryInvalidity):
				return nil, fmt.Errorf("unsupported critical CRL entry extension %s", x.Id)
			}
		}
		k := serialKey(e.SerialNumber)
		if _, dup := l.revoked[k]; !dup {
			l.revoked[k] = &revokedEntry{at: e.RevocationTime, reason: e.ReasonCode}
		}
	}
	return l, nil
}

func oidIn(id asn1.ObjectIdentifier, list []asn1.ObjectIdentifier) bool {
	for _, x := range list {
		if id.Equal(x) {
			return true
		}
	}
	return false
}

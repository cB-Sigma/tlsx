// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package revocation

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// Policy says what a check does when a CA's CRL cannot be used: it was
// never loaded, it could not be read or verified, or it is past its
// nextUpdate time.
type Policy int

const (
	// FailClosed refuses the certificate when the CRL cannot be used.
	// It is the zero value, and so the default for every Source.
	FailClosed Policy = iota
	// FailOpen accepts the certificate when the CRL cannot be used. A
	// certificate listed in the last good CRL is still refused, even if
	// that CRL is stale.
	FailOpen
)

func (p Policy) String() string {
	switch p {
	case FailClosed:
		return "fail-closed"
	case FailOpen:
		return "fail-open"
	}
	return fmt.Sprintf("Policy(%d)", int(p))
}

// Source is the CRL of one CA. Exactly one of File and URL is set.
type Source struct {
	// Issuer is the CA certificate that issues the CRL, and whose
	// certificates the CRL covers. The CRL's issuer name must equal the
	// Issuer's subject and its signature must verify with the Issuer's
	// key. A CA certificate re-issued with the same subject and key
	// shares the Source.
	Issuer *x509.Certificate

	// File is the path of a CRL file, DER or PEM ("X509 CRL").
	File string
	// URL is an http or https URL serving the CRL, DER or PEM.
	URL string

	// Policy applies when this CRL cannot be used. The zero value is
	// FailClosed; FailOpen must be set explicitly.
	Policy Policy

	// Name identifies the source in Status, events and errors. The
	// default is the Issuer's subject.
	Name string
}

// CertChecker is an extension point for revocation mechanisms other than
// CRLs. It is called for each certificate and its issuer in a chain, after
// the CRL check has passed; a non-nil error refuses the certificate.
//
// tlsx v0.2.0 has no implementation. OCSP is planned for a later version
// and would be added here; the interface may change before v1.
type CertChecker interface {
	CheckCertificate(cert, issuer *x509.Certificate) error
}

// Config configures a Checker. Only Sources is required.
type Config struct {
	// Sources lists the CRLs to use, one or more per CA. Several sources
	// for one CA are allowed, for example partitioned CRLs with an
	// issuing distribution point.
	Sources []Source

	// Unchecked lists CA certificates that are trusted but have no CRL.
	// Their certificates are not checked; Status reports them as not
	// configured. CAs met in chains with no Source are reported too.
	Unchecked []*x509.Certificate

	// HTTPClient fetches URL sources. The default is an http.Client with
	// FetchTimeout as its timeout.
	HTTPClient *http.Client
	// FetchTimeout bounds each fetch, file or HTTP. Default 30 seconds.
	FetchTimeout time.Duration
	// MaxCRLSize is the largest CRL accepted, in bytes. Default 16 MiB.
	MaxCRLSize int64

	// RefreshInterval is the time between refreshes of a source. Default
	// one hour.
	RefreshInterval time.Duration
	// RefreshMargin makes a source refresh this long before its CRL's
	// nextUpdate time, if that comes before the next periodic refresh.
	// Default 15 minutes.
	RefreshMargin time.Duration
	// RetryMin and RetryMax bound the back-off after a failed refresh,
	// or after a refresh within the margin that found no newer CRL. The
	// delay doubles from RetryMin up to RetryMax. Defaults 30 seconds and
	// 15 minutes.
	RetryMin, RetryMax time.Duration
	// DisableRefresh turns off background refreshing; sources are then
	// loaded by New and by Refresh only.
	DisableRefresh bool

	// ClockSkew is the tolerance applied to a CRL's thisUpdate (not in
	// the future) and nextUpdate (not in the past). Default zero.
	ClockSkew time.Duration

	// Now returns the current time. Default time.Now. It is for tests.
	Now func() time.Time

	// OnEvent, if set, is called for each Event, for metrics or logging.
	// It is called synchronously, with no locks held, and must not block.
	OnEvent func(Event)

	// Extra holds further checks run after the CRL check (see
	// CertChecker).
	Extra []CertChecker
}

// Checker checks certificate chains against CRLs. It is safe for
// concurrent use. Create it with New and stop it with Close.
type Checker struct {
	cfg      Config
	sources  []*source
	byIssuer map[string][]*source

	mu        sync.Mutex
	unchecked map[string]string // issuer key -> subject, CAs with no Source
	seenOrder []string

	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// maxUnchecked bounds the CAs without a Source that Status remembers.
const maxUnchecked = 64

// New validates cfg, loads every source once and, unless DisableRefresh is
// set, starts refreshing them in the background. A source that fails to
// load is not an error of New: its state is in Status and its Policy
// decides what checks do. New returns an error only for an invalid
// configuration.
func New(cfg Config) (*Checker, error) {
	if cfg.HTTPClient == nil {
		if cfg.FetchTimeout == 0 {
			cfg.FetchTimeout = 30 * time.Second
		}
		cfg.HTTPClient = &http.Client{Timeout: cfg.FetchTimeout}
	}
	setDefault(&cfg.FetchTimeout, 30*time.Second)
	setDefault(&cfg.RefreshInterval, time.Hour)
	setDefault(&cfg.RefreshMargin, 15*time.Minute)
	setDefault(&cfg.RetryMin, 30*time.Second)
	setDefault(&cfg.RetryMax, 15*time.Minute)
	if cfg.MaxCRLSize == 0 {
		cfg.MaxCRLSize = 16 << 20
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	switch {
	case cfg.FetchTimeout < 0, cfg.RefreshInterval < 0, cfg.RefreshMargin < 0,
		cfg.RetryMin < 0, cfg.RetryMax < 0, cfg.ClockSkew < 0, cfg.MaxCRLSize < 0:
		return nil, errors.New("revocation: negative durations and sizes are not allowed")
	case cfg.RetryMax < cfg.RetryMin:
		return nil, errors.New("revocation: RetryMax is less than RetryMin")
	}

	c := &Checker{
		cfg:       cfg,
		byIssuer:  make(map[string][]*source),
		unchecked: make(map[string]string),
	}
	for i, s := range cfg.Sources {
		if s.Issuer == nil {
			return nil, fmt.Errorf("revocation: source %d has no Issuer", i)
		}
		if (s.File == "") == (s.URL == "") {
			return nil, fmt.Errorf("revocation: source %d must set exactly one of File and URL", i)
		}
		if s.URL != "" {
			u, err := url.Parse(s.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return nil, fmt.Errorf("revocation: source %d: URL %q is not an http or https URL", i, s.URL)
			}
		}
		if s.Policy != FailClosed && s.Policy != FailOpen {
			return nil, fmt.Errorf("revocation: source %d: unknown policy %d", i, int(s.Policy))
		}
		src := newSource(c, s)
		c.sources = append(c.sources, src)
		k := issuerKey(s.Issuer)
		c.byIssuer[k] = append(c.byIssuer[k], src)
	}
	for _, ca := range cfg.Unchecked {
		if ca != nil {
			c.noteUnchecked(ca)
		}
	}

	c.ctx, c.cancel = context.WithCancel(context.Background())
	c.refreshAll(c.ctx)
	if !cfg.DisableRefresh {
		for _, s := range c.sources {
			c.wg.Add(1)
			go s.run(c.ctx)
		}
	}
	return c, nil
}

func setDefault(d *time.Duration, v time.Duration) {
	if *d == 0 {
		*d = v
	}
}

// Close stops background refreshing and waits for running fetches to end.
// Checks keep working afterwards with the CRLs already loaded, which
// eventually go stale. Close is idempotent and always returns nil.
func (c *Checker) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.wg.Wait()
	})
	return nil
}

// Refresh fetches every source now, as a background refresh would, and
// returns the errors of the sources that failed, joined. A failed source
// keeps its last good CRL.
func (c *Checker) Refresh(ctx context.Context) error {
	return c.refreshAll(ctx)
}

func (c *Checker) refreshAll(ctx context.Context) error {
	errs := make([]error, len(c.sources))
	var wg sync.WaitGroup
	for i, s := range c.sources {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.refresh(ctx)
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// issuerKey identifies a CA by subject and public key, so that re-issued
// and cross-signed copies of one CA certificate share their CRL sources.
// Both parts are DER elements, so their concatenation is unambiguous.
func issuerKey(ca *x509.Certificate) string {
	return string(ca.RawSubject) + string(ca.RawSubjectPublicKeyInfo)
}

func (c *Checker) noteUnchecked(ca *x509.Certificate) {
	k := issuerKey(ca)
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.unchecked[k]; ok || len(c.unchecked) >= maxUnchecked {
		return
	}
	c.unchecked[k] = ca.Subject.String()
	c.seenOrder = append(c.seenOrder, k)
}

func (c *Checker) emit(e Event) {
	if c.cfg.OnEvent != nil {
		if e.Time.IsZero() {
			e.Time = c.cfg.Now()
		}
		c.cfg.OnEvent(e)
	}
}

// VerifyConnection checks the peer's certificate chains. It has the
// signature of crypto/tls's Config.VerifyConnection and can be assigned to
// it directly. With tlsx, whose ConnectionState is a different type, use
//
//	cfg.VerifyConnection = func(cs tlsx.ConnectionState) error {
//		return checker.CheckChains(cs.VerifiedChains)
//	}
//
// It checks cs.VerifiedChains; if there are none (the peer's chain was not
// verified), it checks cs.PeerCertificates as presented. With no peer
// certificates it returns nil: whether a certificate is required is the
// ClientAuth setting's decision.
func (c *Checker) VerifyConnection(cs tls.ConnectionState) error {
	if len(cs.VerifiedChains) > 0 {
		return c.CheckChains(cs.VerifiedChains)
	}
	if len(cs.PeerCertificates) > 0 {
		return c.CheckChain(cs.PeerCertificates)
	}
	return nil
}

// VerifyPeerCertificate has the signature of Config.VerifyPeerCertificate
// in crypto/tls, tlsx and pion/dtls. It checks verifiedChains; if there
// are none, it parses rawCerts and checks them as presented.
func (c *Checker) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) > 0 {
		return c.CheckChains(verifiedChains)
	}
	if len(rawCerts) == 0 {
		return nil
	}
	chain := make([]*x509.Certificate, 0, len(rawCerts))
	for _, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("revocation: parsing peer certificate: %w", err)
		}
		chain = append(chain, cert)
	}
	return c.CheckChain(chain)
}

// CheckChains checks each chain with CheckChain. Every chain must pass: a
// certificate revoked on one path to a trusted root is refused even if
// another path avoids the revoked CA.
func (c *Checker) CheckChains(chains [][]*x509.Certificate) error {
	for _, chain := range chains {
		if err := c.CheckChain(chain); err != nil {
			return err
		}
	}
	return nil
}

// CheckChain checks a certificate chain, leaf first, such as one of the
// verified chains of crypto/x509's Verify. Each certificate is checked
// against the CRLs of its issuer, the next certificate in the chain. A
// self-issued last certificate is the trust anchor and is not checked. If
// the last certificate is not self-issued, its issuer is looked up among
// the Sources' Issuers.
//
// A certificate whose issuer has no Source is not checked (Status lists
// the issuer as not configured). CheckChain does not verify signatures or
// validity periods: pass it a chain that was verified.
//
// A refused certificate gives an error that matches ErrRevoked (a
// *RevokedError) or ErrUnavailable (an *UnavailableError) with errors.Is.
func (c *Checker) CheckChain(chain []*x509.Certificate) error {
	for i, cert := range chain {
		var issuer *x509.Certificate
		if i+1 < len(chain) {
			issuer = chain[i+1]
		} else {
			if bytes.Equal(cert.RawIssuer, cert.RawSubject) {
				break
			}
			issuer = c.findIssuer(cert)
			if issuer == nil {
				continue
			}
		}
		if err := c.checkCert(cert, issuer); err != nil {
			return err
		}
	}
	return nil
}

// findIssuer returns the Source Issuer that issued cert, or nil.
func (c *Checker) findIssuer(cert *x509.Certificate) *x509.Certificate {
	for _, s := range c.sources {
		if bytes.Equal(cert.RawIssuer, s.issuer.RawSubject) && cert.CheckSignatureFrom(s.issuer) == nil {
			return s.issuer
		}
	}
	return nil
}

func (c *Checker) checkCert(cert, issuer *x509.Certificate) error {
	srcs := c.byIssuer[issuerKey(issuer)]
	if len(srcs) == 0 {
		c.noteUnchecked(issuer)
	} else if err := c.checkCRLs(cert, issuer, srcs); err != nil {
		return err
	}
	for _, x := range c.cfg.Extra {
		if err := x.CheckCertificate(cert, issuer); err != nil {
			return err
		}
	}
	return nil
}

func (c *Checker) checkCRLs(cert, issuer *x509.Certificate, srcs []*source) error {
	now := c.cfg.Now()
	type unusable struct {
		s   *source
		err error
	}
	var bad []unusable
	covered := false
	for _, s := range srcs {
		l, lastErr := s.current()
		switch {
		case l == nil:
			if lastErr == nil {
				lastErr = errors.New("not loaded yet")
			}
			bad = append(bad, unusable{s, fmt.Errorf("no CRL loaded: %w", lastErr)})
		case !l.scope.covers(cert):
			// A partition of the CA's CRLs that does not cover cert.
		case l.revoked[serialKey(cert.SerialNumber)] != nil:
			e := l.revoked[serialKey(cert.SerialNumber)]
			err := &RevokedError{
				Subject:   cert.Subject.String(),
				Serial:    new(big.Int).Set(cert.SerialNumber),
				Issuer:    issuer.Subject.String(),
				Source:    s.name,
				RevokedAt: e.at,
				Reason:    e.reason,
			}
			c.emit(Event{Kind: EventRevoked, Source: s.name, Serial: err.Serial, Err: err})
			return err
		case now.After(l.nextUpdate.Add(c.cfg.ClockSkew)):
			bad = append(bad, unusable{s, fmt.Errorf("CRL is stale: its nextUpdate %s has passed", l.nextUpdate.UTC().Format(time.RFC3339))})
		default:
			covered = true
		}
	}
	for _, b := range bad {
		err := &UnavailableError{Subject: cert.Subject.String(), Source: b.s.name, Err: b.err}
		allowed := b.s.policy == FailOpen
		c.emit(Event{Kind: EventUnavailable, Source: b.s.name, Serial: cert.SerialNumber, Err: err, Allowed: allowed})
		if !allowed {
			return err
		}
	}
	if !covered && len(bad) == 0 {
		// Every loaded CRL of this CA is a partition that excludes cert.
		closed := false
		for _, s := range srcs {
			closed = closed || s.policy == FailClosed
		}
		err := &UnavailableError{Subject: cert.Subject.String(), Source: srcs[0].name,
			Err: errors.New("no CRL of the issuer covers this certificate (issuing distribution point)")}
		c.emit(Event{Kind: EventUnavailable, Source: srcs[0].name, Serial: cert.SerialNumber, Err: err, Allowed: !closed})
		if closed {
			return err
		}
	}
	return nil
}

// ErrRevoked is matched by the errors of revoked certificates.
var ErrRevoked = errors.New("revocation: certificate is revoked")

// ErrUnavailable is matched by the errors of certificates refused because
// a CRL could not be used under FailClosed.
var ErrUnavailable = errors.New("revocation: no usable CRL")

// RevokedError reports a certificate listed in its issuer's CRL.
type RevokedError struct {
	Subject   string   // the revoked certificate's subject
	Serial    *big.Int // its serial number
	Issuer    string   // its issuer's subject
	Source    string   // the Source whose CRL lists it
	RevokedAt time.Time
	Reason    int // CRL reason code (RFC 5280 5.3.1); 0 if absent
}

func (e *RevokedError) Error() string {
	return fmt.Sprintf("revocation: certificate %q (serial %s) of %q was revoked at %s, reason %s (CRL %q)",
		e.Subject, e.Serial.Text(16), e.Issuer, e.RevokedAt.UTC().Format(time.RFC3339), ReasonString(e.Reason), e.Source)
}

// Is makes errors.Is(err, ErrRevoked) true.
func (e *RevokedError) Is(target error) bool { return target == ErrRevoked }

// UnavailableError reports a certificate that could not be checked because
// its issuer's CRL is missing, unreadable or stale.
type UnavailableError struct {
	Subject string // the certificate's subject
	Source  string // the Source that could not be used
	Err     error  // why
}

func (e *UnavailableError) Error() string {
	return fmt.Sprintf("revocation: cannot check certificate %q: CRL %q: %v", e.Subject, e.Source, e.Err)
}

// Is makes errors.Is(err, ErrUnavailable) true.
func (e *UnavailableError) Is(target error) bool { return target == ErrUnavailable }

func (e *UnavailableError) Unwrap() error { return e.Err }

// ReasonString names a CRL reason code of RFC 5280 5.3.1.
func ReasonString(code int) string {
	names := [...]string{"unspecified", "keyCompromise", "cACompromise",
		"affiliationChanged", "superseded", "cessationOfOperation",
		"certificateHold", "", "removeFromCRL", "privilegeWithdrawn", "aACompromise"}
	if code >= 0 && code < len(names) && names[code] != "" {
		return names[code]
	}
	return fmt.Sprintf("reason(%d)", code)
}

// EventKind classifies an Event.
type EventKind int

const (
	// EventLoaded: a source accepted a new CRL.
	EventLoaded EventKind = iota
	// EventUnchanged: a refresh found the same CRL number again.
	EventUnchanged
	// EventRefreshFailed: a refresh failed (fetch, parse, signature,
	// rollback); the source keeps its last good CRL.
	EventRefreshFailed
	// EventRevoked: a check refused a revoked certificate.
	EventRevoked
	// EventUnavailable: a check found no usable CRL. Allowed says
	// whether FailOpen let the certificate through.
	EventUnavailable
)

func (k EventKind) String() string {
	switch k {
	case EventLoaded:
		return "loaded"
	case EventUnchanged:
		return "unchanged"
	case EventRefreshFailed:
		return "refresh-failed"
	case EventRevoked:
		return "revoked"
	case EventUnavailable:
		return "unavailable"
	}
	return fmt.Sprintf("EventKind(%d)", int(k))
}

// Event is passed to Config.OnEvent.
type Event struct {
	Kind    EventKind
	Source  string
	Time    time.Time
	Err     error    // EventRefreshFailed, EventRevoked, EventUnavailable
	Number  *big.Int // CRL number, EventLoaded and EventUnchanged
	Serial  *big.Int // certificate serial, EventRevoked and EventUnavailable
	Allowed bool     // EventUnavailable under FailOpen
}

// State is the state of a source in Status.
type State string

const (
	StateOK            State = "ok"             // a current CRL is loaded
	StateStale         State = "stale"          // the loaded CRL is past its nextUpdate
	StateMissing       State = "missing"        // no CRL could be loaded yet
	StateNotConfigured State = "not configured" // a CA with no Source; not checked
)

// SourceStatus describes one source, or one CA without a source.
type SourceStatus struct {
	Name     string
	Location string // file path or URL; empty when not configured
	Issuer   string // the CA's subject
	Policy   Policy
	State    State
	// Stale is true when a CRL is loaded and past its nextUpdate.
	Stale bool

	LastFetch   time.Time // last refresh attempt
	LastSuccess time.Time // last refresh that fetched a valid CRL
	NextRefresh time.Time // next background refresh
	LastError   string    // error of the last attempt; empty if it succeeded

	ThisUpdate, NextUpdate time.Time // of the loaded CRL
	Number                 *big.Int  // CRL number of the loaded CRL, if any
	Revoked                int       // entries in the loaded CRL
}

// Status returns the state of every source, in configuration order,
// followed by the CAs without a source (Config.Unchecked, then those met
// in chains, at most 64).
func (c *Checker) Status() []SourceStatus {
	now := c.cfg.Now()
	out := make([]SourceStatus, 0, len(c.sources))
	for _, s := range c.sources {
		out = append(out, s.status(now))
	}
	c.mu.Lock()
	var rest []SourceStatus
	for _, k := range c.seenOrder {
		if _, ok := c.byIssuer[k]; ok {
			continue
		}
		rest = append(rest, SourceStatus{Name: c.unchecked[k], Issuer: c.unchecked[k], State: StateNotConfigured})
	}
	c.mu.Unlock()
	return append(out, rest...)
}

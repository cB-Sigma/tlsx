// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

// Package revocation checks certificate chains against certificate
// revocation lists (CRLs, RFC 5280 section 5). Neither crypto/tls nor tlsx
// checks revocation; they leave it to the application's VerifyConnection
// hook. This package is that hook. It depends only on the standard library
// and golang.org/x/crypto/cryptobyte, and works with crypto/tls, tlsx and
// other stacks that hand over verified chains, such as pion/dtls.
//
// # Use
//
// Configure one Source per CA whose certificates should be checked, with
// the CA certificate and a CRL file or URL, and create a Checker:
//
//	chk, err := revocation.New(revocation.Config{
//		Sources: []revocation.Source{
//			{Issuer: deviceCA, URL: "http://pki.example/device-ca.crl"},
//			{Issuer: rootCA, File: "/etc/pki/root.crl"},
//		},
//	})
//	if err != nil { ... }
//	defer chk.Close()
//
// With crypto/tls, assign its method to the Config:
//
//	cfg := &tls.Config{
//		ClientAuth:       tls.RequireAndVerifyClientCert,
//		ClientCAs:        pool,
//		VerifyConnection: chk.VerifyConnection,
//	}
//
// With tlsx, whose ConnectionState is its own type, pass the verified
// chains:
//
//	cfg.VerifyConnection = func(cs tlsx.ConnectionState) error {
//		return chk.CheckChains(cs.VerifiedChains)
//	}
//
// VerifyPeerCertificate has the signature of Config.VerifyPeerCertificate
// in crypto/tls, tlsx and pion/dtls, and CheckChain checks one chain from
// any source.
//
// # What is checked
//
// Every certificate of each verified chain except the trust anchor: the
// leaf and every intermediate, each against the CRLs of the certificate
// that issued it. A CRL is used only if its issuer name equals the CA's
// subject, its signature verifies with the CA's key (and the CA may sign
// CRLs), its thisUpdate is not in the future and it has a nextUpdate.
// Every chain must pass, so a revoked intermediate on one path is refused
// even if another path avoids it.
//
// # Failure policy
//
// FailClosed is the default (the zero Policy) for every Source: when the
// CRL was never loaded, could not be read or verified, or is past its
// nextUpdate, certificates of that CA are refused with an error matching
// ErrUnavailable. FailOpen lets them through instead and must be set on
// the Source explicitly; it still refuses certificates listed in the last
// good CRL. A CA with no Source is not checked at all; Status lists it as
// "not configured". Revoked certificates are refused with an error
// matching ErrRevoked, including those on hold (certificateHold).
//
// # Refresh
//
// New loads every source once. Unless Config.DisableRefresh is set, each
// source is then refreshed in the background every RefreshInterval, and
// RefreshMargin before its CRL's nextUpdate if that is sooner. Failures
// back off from RetryMin to RetryMax. A source keeps its last good CRL
// until a newer one verifies. A CRL is replaced only by one with a higher
// CRL number; a lower number is refused as a rollback, and the same number
// is taken as the same CRL. (For CRLs without numbers, thisUpdate is
// compared.) The rollback check is in memory: it does not survive a
// restart. HTTP fetches use Config.HTTPClient, a per-fetch timeout and a
// size limit (MaxCRLSize). Close stops refreshing.
//
// # Status and events
//
// Status reports, per source, the last fetch and success times, the CRL's
// thisUpdate, nextUpdate and number, its number of entries, the last error
// and whether it is stale, and lists CAs without a source. Config.OnEvent
// receives loads, failed refreshes, revoked certificates and unavailable
// CRLs, for metrics or logging.
//
// # Limits
//
//   - No OCSP. It is planned; CertChecker (Config.Extra) is the extension
//     point where it would plug in.
//   - No delta CRLs. A CRL with the delta CRL indicator is refused, so a
//     delta is never taken for a complete CRL; the freshest CRL extension
//     of a base CRL is ignored.
//   - Issuing distribution points: a CRL scoped to user or CA certificates
//     or to distribution point URIs (partitioned CRLs) is applied to the
//     certificates it covers; a certificate that no loaded CRL of its CA
//     covers is treated as unavailable. Reason partitions, indirect CRLs
//     and distribution point names that are not URIs are refused.
//   - Unknown critical CRL or entry extensions make a CRL unusable.
//   - A CRL must be issued by the CA itself; a separate CRL signing key
//     certified by the CA is not supported.
//   - No conditional HTTP requests (ETag, If-Modified-Since).
package revocation

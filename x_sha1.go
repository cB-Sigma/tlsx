// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.

package tlsx

import (
	"crypto"
	"slices"
)

// SHA-1 signatures in TLS 1.2 handshakes (RSA PKCS #1 v1.5 and ECDSA with
// SHA-1). Go 1.25 turned them off; GODEBUG tlssha1=1 turns them on for the
// whole process, and Config.Ext.AllowSHA1Signatures for one Config. The
// upstream code decides with tlssha1 alone; the hooks below add the
// Config's permission where a Config is at hand.

// sha1SchemesX are the TLS 1.2 SHA-1 signature schemes, in the order Go
// lists them.
var sha1SchemesX = []SignatureScheme{PKCS1WithSHA1, ECDSAWithSHA1}

func isSHA1SchemeX(s SignatureScheme) bool { return slices.Contains(sha1SchemesX, s) }

// allowSHA1X reports whether c allows SHA-1 signatures beyond what GODEBUG
// allows (GODEBUG tlssha1=1 already allows them everywhere).
func (c *Config) allowSHA1X() bool {
	return c != nil && c.Ext.AllowSHA1Signatures && tlssha1.Value() != "1"
}

// selectSignatureSchemeX is selectSignatureScheme with the Config's SHA-1
// permission (TLS 1.2): a SHA-1 scheme is taken where the peer prefers it
// to the one selectSignatureScheme picked, or where nothing else fits, if
// the key can make it and the certificate's SupportedSignatureAlgorithms
// allow it. A TLS 1.2 peer without signature_algorithms is taken to accept
// SHA-1 (RFC 5246 7.4.1.4.1), as with tlssha1=1.
func selectSignatureSchemeX(config *Config, vers uint16, c *Certificate, peerAlgs []SignatureScheme) (SignatureScheme, error) {
	alg, err := selectSignatureScheme(vers, c, peerAlgs)
	if vers != VersionTLS12 || !config.allowSHA1X() {
		return alg, err
	}
	priv, ok := c.PrivateKey.(crypto.Signer)
	if !ok {
		return alg, err
	}
	own := signatureSchemesForOwnX(vers, c, priv.Public())
	if len(peerAlgs) == 0 {
		peerAlgs = sha1SchemesX
	}
	for _, p := range peerAlgs {
		if err == nil && p == alg {
			return alg, nil
		}
		if isSHA1SchemeX(p) && slices.Contains(own, p) &&
			(c.SupportedSignatureAlgorithms == nil || slices.Contains(c.SupportedSignatureAlgorithms, p)) {
			return p, nil
		}
	}
	return alg, err
}

// supportsCertificateX is cri.SupportsCertificate for a client whose
// Config allows SHA-1 signatures: a certificate that can answer the
// CertificateRequest only with a SHA-1 signature is checked against the
// rest of the request (the acceptable CAs) as one that can sign otherwise.
func (config *Config) supportsCertificateX(cri *CertificateRequestInfo, c *Certificate) error {
	err := cri.SupportsCertificate(c)
	if err == nil || cri.Version != VersionTLS12 || !config.allowSHA1X() {
		return err
	}
	s, serr := selectSignatureSchemeX(config, cri.Version, c, cri.SignatureSchemes)
	priv, ok := c.PrivateKey.(crypto.Signer)
	if serr != nil || !isSHA1SchemeX(s) || !ok {
		return err
	}
	rest := *cri
	rest.SignatureSchemes = slices.DeleteFunc(signatureSchemesForOwnX(cri.Version, c, priv.Public()), isSHA1SchemeX)
	return rest.SupportsCertificate(c)
}

// sigAlgsSHA1X adds the SHA-1 schemes to a TLS 1.2 signature_algorithms
// list when the Config allows them (configured: those of
// Config.Ext.SignatureSchemes; otherwise both, last, as tlssha1=1 does).
func (c *Config) sigAlgsSHA1X(algs []SignatureScheme, version uint16) []SignatureScheme {
	if version > VersionTLS12 || !c.allowSHA1X() {
		return algs
	}
	add := sha1SchemesX
	if len(c.Ext.SignatureSchemes) > 0 {
		add = slices.DeleteFunc(slices.Clone(c.Ext.SignatureSchemes), func(s SignatureScheme) bool { return !isSHA1SchemeX(s) })
	}
	for _, s := range add {
		if !slices.Contains(algs, s) {
			algs = append(algs, s)
		}
	}
	return algs
}

// noteSigAlg records a signature scheme used in the handshake, by either
// side (ConnectionState().Ext.SHA1Signature).
func (x *connExt) noteSigAlg(s SignatureScheme) {
	if s != 0 {
		x.sha1Sig = x.sha1Sig || isSHA1SchemeX(s)
	}
}

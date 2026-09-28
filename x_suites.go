// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package tlsx

import (
	"crypto"
	"crypto/aes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"slices"

	"golang.org/x/crypto/cryptobyte"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/ccm"
)

// Cipher suites tlsx adds. None is used unless Config.CipherSuites (TLS
// 1.2) or Config.Ext.CipherSuitesTLS13 (TLS 1.3) lists it.
//
//   - TLS_DHE_RSA_WITH_AES_128/256_GCM (RFC 5288) with the RFC 7919
//     groups only;
//   - TLS_ECDHE_ECDSA/RSA_WITH_AES_256_CBC_SHA384 (RFC 5289);
//   - TLS_AES_128_CCM_SHA256 (RFC 8446 B.4) over internal/ccm.
//
// CBC suites (upstream's and these) use encrypt_then_mac (RFC 7366) when
// both sides offer it; Config.Ext.RequireEncryptThenMAC makes it a
// condition.

// suiteDHE marks a finite field DHE suite (a tlsx cipherSuite flag).
const suiteDHE = 1 << 10

var tlsxSuiteNames = map[uint16]string{
	TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:     "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
	TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:     "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
	TLS_AES_128_CCM_SHA256:                  "TLS_AES_128_CCM_SHA256",
	TLS_AES_128_CCM_8_SHA256:                "TLS_AES_128_CCM_8_SHA256",
	TLS_SHA256_SHA256:                       "TLS_SHA256_SHA256",
	TLS_SHA384_SHA384:                       "TLS_SHA384_SHA384",
	TLS_RSA_WITH_NULL_SHA256:                "TLS_RSA_WITH_NULL_SHA256",
	TLS_DH_RSA_WITH_AES_128_GCM_SHA256:      "TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
}

func cipherSuiteNameX(id uint16) (string, bool) {
	n, ok := tlsxSuiteNames[id]
	return n, ok
}

func init() {
	cipherSuites = append(cipherSuites,
		&cipherSuite{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, dheRSAKA, suiteDHE | suiteTLS12, nil, nil, aeadAESGCM},
		&cipherSuite{TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, dheRSAKA, suiteDHE | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
		&cipherSuite{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
		&cipherSuite{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, macSHA384, nil},
		&cipherSuite{TLS_RSA_WITH_NULL_SHA256, 0, 32, 0, rsaKA, suiteTLS12, cipherNull, macSHA256, nil},
		&cipherSuite{TLS_DH_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, staticDHKA, suiteStaticDH | suiteTLS12, nil, nil, aeadAESGCM},
	)
	cipherSuitesTLS13 = append(cipherSuitesTLS13,
		&cipherSuiteTLS13{TLS_AES_128_CCM_SHA256, 16, aeadAESCCMTLS13, crypto.SHA256},
		&cipherSuiteTLS13{TLS_AES_128_CCM_8_SHA256, 16, aeadAESCCM8TLS13, crypto.SHA256},
		&cipherSuiteTLS13{TLS_SHA256_SHA256, 32, aeadHMACSHA256, crypto.SHA256},
		&cipherSuiteTLS13{TLS_SHA384_SHA384, 48, aeadHMACSHA384, crypto.SHA384},
	)
	// Preference: DHE AEADs after the ECDHE AEADs, the SHA-384 CBC suites
	// next to the SHA-256 ones (all off by default).
	dhe := []uint16{TLS_DHE_RSA_WITH_AES_128_GCM_SHA256, TLS_DHE_RSA_WITH_AES_256_GCM_SHA384, TLS_DH_RSA_WITH_AES_128_GCM_SHA256}
	cbc384 := []uint16{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384}
	for _, l := range []*[]uint16{&cipherSuitesPreferenceOrder, &cipherSuitesPreferenceOrderNoAES} {
		i := slices.Index(*l, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)
		*l = slices.Insert(*l, i, dhe...)
		j := slices.Index(*l, TLS_RSA_WITH_AES_128_CBC_SHA256) + 1
		*l = slices.Insert(*l, j, cbc384...)
	}
	for _, l := range []*[]uint16{&cipherSuitesPreferenceOrder, &cipherSuitesPreferenceOrderNoAES} {
		*l = append(*l, TLS_RSA_WITH_NULL_SHA256) // last of all
	}
	for _, id := range append(dhe, cbc384...) {
		disabledCipherSuites[id] = true
	}
	disabledCipherSuites[TLS_RSA_WITH_NULL_SHA256] = true
}

// macSHA384 is HMAC-SHA384 (RFC 5289 CBC suites).
func macSHA384(key []byte) hash.Hash { return hmac.New(sha512.New384, key) }

// aeadAESCCMTLS13 and aeadAESCCM8TLS13 are adapted from Go's
// crypto/tls/cipher_suites.go: aeadAESGCMTLS13 (with AES-CCM in place of
// AES-GCM). Copyright The Go Authors, BSD-3-Clause; see NOTICE.
//
// aeadAESCCMTLS13 is AES-128-CCM with a 16-byte tag and the TLS 1.3 nonce
// construction (RFC 8446 5.3).
func aeadAESCCMTLS13(key, nonceMask []byte) aead {
	if len(nonceMask) != aeadNonceLength {
		panic("tls: internal error: wrong nonce length")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	a, err := ccm.New(b, aeadNonceLength, 16)
	if err != nil {
		panic(err)
	}
	ret := &xorNonceAEAD{aead: a}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// aeadAESCCM8TLS13 is AES-128-CCM with an 8-byte tag (RFC 8446 B.4,
// TLS_AES_128_CCM_8_SHA256).
func aeadAESCCM8TLS13(key, nonceMask []byte) aead {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	a, err := ccm.New(b, aeadNonceLength, 8)
	if err != nil {
		panic(err)
	}
	ret := &xorNonceAEAD{aead: a}
	copy(ret.nonceMask[:], nonceMask)
	return ret
}

// ivLen is the TLS 1.3 IV length of a suite: the hash length for the
// integrity-only suites (RFC 9150 6), 12 otherwise.
func (c *cipherSuiteTLS13) ivLen() int {
	switch c.id {
	case TLS_SHA256_SHA256, TLS_SHA384_SHA384:
		return c.hash.Size()
	}
	return aeadNonceLength
}

// IsIntegrityOnly reports a cipher suite without confidentiality (RFC
// 9150).
func IsIntegrityOnly(id uint16) bool {
	return id == TLS_SHA256_SHA256 || id == TLS_SHA384_SHA384 || id == TLS_RSA_WITH_NULL_SHA256
}

// cipherNull is the NULL "cipher" of TLS_RSA_WITH_NULL_SHA256: records
// carry the plaintext and the HMAC (the upstream stream-cipher path with
// an identity key stream).
func cipherNull(key, iv []byte, isRead bool) any { return nullStream{} }

type nullStream struct{}

func (nullStream) XORKeyStream(dst, src []byte) { copy(dst, src) }

func aeadHMACSHA256(key, iv []byte) aead { return newHMACAEAD(sha256.New, key, iv) }
func aeadHMACSHA384(key, iv []byte) aead { return newHMACAEAD(sha512.New384, key, iv) }

// hmacAEAD is the record protection of the integrity-only suites (RFC
// 9150 5): the "ciphertext" is the TLSInnerPlaintext followed by
// HMAC(key, nonce || additional_data || TLSInnerPlaintext), the nonce
// the IV (hash length) XORed with the padded sequence number.
type hmacAEAD struct {
	mac   hash.Hash
	iv    []byte
	nonce []byte
}

func newHMACAEAD(h func() hash.Hash, key, iv []byte) *hmacAEAD {
	if len(iv) != h().Size() || len(key) != h().Size() {
		panic("tls: internal error: wrong integrity-only key or IV length")
	}
	return &hmacAEAD{mac: hmac.New(h, key), iv: slices.Clone(iv), nonce: make([]byte, len(iv))}
}

func (a *hmacAEAD) NonceSize() int        { return 8 } // the sequence number
func (a *hmacAEAD) Overhead() int         { return a.mac.Size() }
func (a *hmacAEAD) explicitNonceLen() int { return 0 }

func (a *hmacAEAD) tag(seq, plaintext, ad []byte) []byte {
	copy(a.nonce, a.iv)
	off := len(a.nonce) - len(seq)
	for i, b := range seq {
		a.nonce[off+i] ^= b
	}
	a.mac.Reset()
	a.mac.Write(a.nonce)
	a.mac.Write(ad)
	a.mac.Write(plaintext)
	return a.mac.Sum(nil)
}

func (a *hmacAEAD) Seal(dst, seq, plaintext, ad []byte) []byte {
	t := a.tag(seq, plaintext, ad)
	ret, out := sliceForAppend(dst, len(plaintext)+len(t))
	copy(out, plaintext)
	copy(out[len(plaintext):], t)
	return ret
}

func (a *hmacAEAD) Open(dst, seq, ciphertext, ad []byte) ([]byte, error) {
	n := len(ciphertext) - a.mac.Size()
	if n < 0 {
		return nil, errors.New("tlsx: short integrity-only record")
	}
	if !hmac.Equal(a.tag(seq, ciphertext[:n], ad), ciphertext[n:]) {
		return nil, errors.New("tlsx: record HMAC mismatch")
	}
	ret, out := sliceForAppend(dst, n)
	copy(out, ciphertext[:n])
	return ret, nil
}

func isCBCSuite(s *cipherSuite) bool {
	return s != nil && s.cipher != nil && s.aead == nil && s.macLen > 0 && s.id != TLS_RSA_WITH_NULL_SHA256
}

// cipherSuiteOkX decides for the suites tlsx cares about: DHE needs an
// RSA signing key and a usable group; with RequireEncryptThenMAC a CBC
// suite needs the client's encrypt_then_mac.
func (hs *serverHandshakeState) cipherSuiteOkX(c *cipherSuite) (ok, decided bool) {
	cfg := hs.c.config
	if c.flags&suitePSK != 0 {
		if isCBCSuite(c) && cfg.Ext.RequireEncryptThenMAC && !hs.clientHello.x.encryptThenMAC {
			return false, true
		}
		return hs.cipherSuiteOkPSK(c), true
	}
	if isCBCSuite(c) && cfg.Ext.RequireEncryptThenMAC && !hs.clientHello.x.encryptThenMAC {
		return false, true
	}
	if c.flags&suiteDHE != 0 {
		return hs.rsaSignOk && hs.c.vers >= VersionTLS12 && hs.dheGroup() != nil, true
	}
	if c.flags&suiteStaticDH != 0 {
		dc := cfg.Ext.StaticDHCertificate
		if dc == nil || hs.c.vers < VersionTLS12 {
			return false, true
		}
		_, ok := dc.PrivateKey.(*DHPrivateKey)
		return ok, true
	}
	return false, false
}

// dheGroup is the RFC 7919 group for a DHE suite: the first of our
// preferences the client lists; if the client lists no finite field group
// (a client from before RFC 7919), our first one.
func (hs *serverHandshakeState) dheGroup() *ffdheGroup {
	return selectDHEGroup(hs.c.config, hs.clientHello)
}

func selectDHEGroup(config *Config, ch *clientHelloMsg) *ffdheGroup {
	ours := slices.DeleteFunc(config.curvePreferences(VersionTLS12), func(id CurveID) bool { return !isFFDHE(id) })
	if len(ours) == 0 {
		return nil
	}
	offersAny := slices.ContainsFunc(ch.supportedCurves, isFFDHE)
	for _, id := range ours {
		if !offersAny || slices.Contains(ch.supportedCurves, id) {
			return ffdheGroups[id]
		}
	}
	return nil
}

func dheRSAKA(version uint16) keyAgreement { return &dheKeyAgreement{version: version} }

// dheKeyAgreement is the TLS 1.2 DHE_RSA key exchange (RFC 5246 7.4.3) on
// the RFC 7919 groups. A server sends only those groups; a client accepts
// only those (by prime and generator) and only one it offered, if it
// offered any, so small or custom groups are refused.
type dheKeyAgreement struct {
	version            uint16
	group              CurveID
	signatureAlgorithm SignatureScheme
	g                  *ffdheGroup
	priv               []byte
	ckx                *clientKeyExchangeMsg
	preMasterSecret    []byte
}

func dheParams(g *ffdheGroup, y []byte) []byte {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(g.pBytes) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(2) })
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(y) })
	return b.BytesOrPanic()
}

// dheKeyAgreement follows the structure of Go's ecdheKeyAgreement in
// src/crypto/tls/key_agreement.go (Copyright 2010 The Go Authors; see
// NOTICE); the signing steps of generateServerKeyExchange are adapted from
// it, with finite field Diffie-Hellman (RFC 7919 groups) in place of ECDHE.
func (ka *dheKeyAgreement) generateServerKeyExchange(config *Config, cert *Certificate, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
	ka.g = selectDHEGroup(config, clientHello)
	if ka.g == nil {
		return nil, errors.New("tlsx: no finite field group for DHE")
	}
	ka.group = ka.g.id
	priv, pub, err := ka.g.generate(config.rand())
	if err != nil {
		return nil, err
	}
	ka.priv = priv
	params := dheParams(ka.g, pub)
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("tls: certificate private key of type %T does not implement crypto.Signer", cert.PrivateKey)
	}
	ka.signatureAlgorithm, err = selectSignatureScheme(ka.version, cert, clientHello.supportedSignatureAlgorithms)
	if err != nil {
		return nil, err
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(ka.signatureAlgorithm)
	if err != nil {
		return nil, err
	}
	if sigType != signaturePKCS1v15 && sigType != signatureRSAPSS {
		return nil, errors.New("tls: certificate cannot be used with the selected cipher suite")
	}
	opts := crypto.SignerOpts(sigHash)
	if sigType == signatureRSAPSS {
		opts = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: sigHash}
	}
	sig, err := crypto.SignMessage(signer, config.rand(), slices.Concat(clientHello.random, hello.random, params), opts)
	if err != nil {
		return nil, errors.New("tls: failed to sign DHE parameters: " + err.Error())
	}
	var b cryptobyte.Builder
	b.AddBytes(params)
	b.AddUint16(uint16(ka.signatureAlgorithm))
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sig) })
	return &serverKeyExchangeMsg{key: b.BytesOrPanic()}, nil
}

func (ka *dheKeyAgreement) processClientKeyExchange(config *Config, cert *Certificate, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
	s := cryptobyte.String(ckx.ciphertext)
	var yc []byte
	if !readUint16LengthPrefixed(&s, &yc) || !s.Empty() || len(yc) == 0 {
		return nil, errClientKeyExchange
	}
	z, err := ka.g.shared(ka.priv, yc)
	if err != nil {
		return nil, errClientKeyExchange
	}
	return trimZeros(z), nil // RFC 5246 8.1.2: leading zero bytes stripped
}

func (ka *dheKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, cert *x509.Certificate, skx *serverKeyExchangeMsg) error {
	s := cryptobyte.String(skx.key)
	var p, g, ys []byte
	if !readUint16LengthPrefixed(&s, &p) || !readUint16LengthPrefixed(&s, &g) || !readUint16LengthPrefixed(&s, &ys) {
		return errServerKeyExchange
	}
	params := skx.key[:len(skx.key)-len(s)]
	var alg uint16
	var sig []byte
	if !s.ReadUint16(&alg) || !readUint16LengthPrefixed(&s, &sig) || !s.Empty() {
		return errServerKeyExchange
	}
	ka.g = ffdheGroupByParams(p, g)
	if ka.g == nil {
		return errors.New("tlsx: server offered a finite field group that is not one of RFC 7919")
	}
	ka.group = ka.g.id
	if slices.ContainsFunc(clientHello.supportedCurves, isFFDHE) && !slices.Contains(clientHello.supportedCurves, ka.group) {
		return errors.New("tlsx: server selected an unoffered finite field group")
	}
	if !config.supportsCurve(VersionTLS12, ka.group) {
		return errors.New("tlsx: server selected a finite field group not allowed by the configuration")
	}
	ka.signatureAlgorithm = SignatureScheme(alg)
	if !isSupportedSignatureAlgorithm(ka.signatureAlgorithm, clientHello.supportedSignatureAlgorithms) {
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err := typeAndHashFromSignatureScheme(ka.signatureAlgorithm)
	if err != nil {
		return err
	}
	if sigType != signaturePKCS1v15 && sigType != signatureRSAPSS {
		return errServerKeyExchange
	}
	if err := verifyHandshakeSignature(sigType, cert.PublicKey, sigHash, slices.Concat(clientHello.random, serverHello.random, params), sig); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	priv, pub, err := ka.g.generate(config.rand())
	if err != nil {
		return err
	}
	z, err := ka.g.shared(priv, ys)
	if err != nil {
		return errServerKeyExchange
	}
	ka.preMasterSecret = trimZeros(z)
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(pub) })
	ka.ckx = &clientKeyExchangeMsg{ciphertext: b.BytesOrPanic()}
	return nil
}

func (ka *dheKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	if ka.ckx == nil {
		return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	}
	return ka.preMasterSecret, ka.ckx, nil
}

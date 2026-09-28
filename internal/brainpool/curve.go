// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

// Package brainpool implements the elliptic curves brainpoolP256r1,
// brainpoolP384r1 and brainpoolP512r1 (RFC 5639) for use by our fork of
// crypto/tls: ECDHE with the TLS named curves of RFC 7027 (26, 27, 28 in
// TLS 1.2; the TLS 1.3 groups 31, 32, 33 use the same curves) and ECDSA with
// brainpool keys, including DER key encodings and X.509 certificates whose
// keys or issuers are on these curves (crypto/x509 only knows the NIST
// curves).
//
// # Arithmetic
//
// Field and scalar arithmetic use the constant-time package
// internal/bigmod; field elements are kept in Montgomery form. Points
// are in homogeneous projective coordinates and are added with the complete
// addition law of Renes, Costello and Batina (EUROCRYPT 2016, algorithm 1,
// valid for any a); the same law is used for doubling, so no input — the
// identity, P+P or P+(-P) — takes a different code path. The brainpool r1
// curves have prime order (cofactor 1), which the complete law requires.
//
// Scalar multiplication uses a fixed 4-bit window: 64/96/128 windows of four
// doublings and one addition each, with the table entry chosen by scanning
// all 16 entries through bigmod's masked select.
//
// # What is constant time, and what is not
//
//   - Constant time with respect to secret scalars: scalar multiplication,
//     ECDH, key generation after the rejection-sampling loop, ECDSA signing
//     (k*G, k^-1 by Fermat exponentiation with bigmod.Exp, s = k^-1(e + r*d)).
//   - Rejection sampling of private keys and of ECDSA nonces leaks how many
//     candidates were rejected (never anything about the accepted value).
//   - Conversions between bytes and bigmod values leak only lengths.
//   - Converting a result to affine form inverts Z with a fixed-exponent
//     exponentiation (constant time).
//   - Verification, public-key validation, DER parsing and marshalling, and
//     every method taking or returning *big.Int (the elliptic.Curve methods,
//     *ecdsa.PublicKey and ecdsa.PrivateKey conversion) are variable time and
//     must only see public data. crypto/ecdsa's generic code path for
//     non-NIST curves (used when an *ecdsa.PrivateKey from ECDSA() is passed
//     to ecdsa.Sign) uses math/big and is not constant time; sign with
//     PrivateKey.Sign instead.
//
// # ECDSA nonces
//
// PrivateKey.Sign derives k deterministically as in RFC 6979 (HMAC-DRBG with
// SHA-256/384/512 matching the curve size) and feeds 32 bytes from the
// caller's random source in as additional input (the hedged variant of
// RFC 6979 section 3.6): a broken RNG does not reveal the key, and a good one
// makes signatures non-deterministic.
//
// # elliptic.CurveParams
//
// Params() returns the curve's p, n, b, G and name. CurveParams' own
// arithmetic methods assume a = -3 and give wrong answers for these curves;
// always call the methods on the curve returned by P256r1() and friends.
package brainpool

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/cB-Abhinav-Gautam/tlsx/internal/bigmod"
)

// Curve parameters (RFC 5639 section 3.4, 3.6, 3.7), cross-checked in tests
// against OpenSSL's explicit parameters.
const (
	p256p  = "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377"
	p256a  = "7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9"
	p256b  = "26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6"
	p256gx = "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"
	p256gy = "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
	p256n  = "A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7"

	p384p  = "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B412B1DA197FB71123ACD3A729901D1A71874700133107EC53"
	p384a  = "7BC382C63D8C150C3C72080ACE05AFA0C2BEA28E4FB22787139165EFBA91F90F8AA5814A503AD4EB04A8C7DD22CE2826"
	p384b  = "04A8C7DD22CE28268B39B55416F0447C2FB77DE107DCD2A62E880EA53EEB62D57CB4390295DBC9943AB78696FA504C11"
	p384gx = "1D1C64F068CF45FFA2A63A81B7C13F6B8847A3E77EF14FE3DB7FCAFE0CBD10E8E826E03436D646AAEF87B2E247D4AF1E"
	p384gy = "8ABE1D7520F9C2A45CB1EB8E95CFD55262B70B29FEEC5864E19C054FF99129280E4646217791811142820341263C5315"
	p384n  = "8CB91E82A3386D280F5D6F7E50E641DF152F7109ED5456B31F166E6CAC0425A7CF3AB6AF6B7FC3103B883202E9046565"

	p512p  = "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA703308717D4D9B009BC66842AECDA12AE6A380E62881FF2F2D82C68528AA6056583A48F3"
	p512a  = "7830A3318B603B89E2327145AC234CC594CBDD8D3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CA"
	p512b  = "3DF91610A83441CAEA9863BC2DED5D5AA8253AA10A2EF1C98B9AC8B57F1117A72BF2C7B9E7C1AC4D77FC94CADC083E67984050B75EBAE5DD2809BD638016F723"
	p512gx = "81AEE4BDD82ED9645A21322E9C4C6A9385ED9F70B5D916C1B43B62EEF4D0098EFF3B1F78E2D0D48D50D1687B93B97D5F7C6D5047406A5E688B352209BCB9F822"
	p512gy = "7DDE385D566332ECC0EABFA9CF7822FDF209F70024A57B1AA000C55B881F8111B2DCDE494A5F485E5BCA4BD88A2763AED1CA2B2FA8F0540678CD1E0F3AD80892"
	p512n  = "AADD9DB8DBE9C48B3FD4E6AE33C9FC07CB308DB3B3C9D20ED6639CCA70330870553E5C414CA92619418661197FAC10471DB1D381085DDADDB58796829CA90069"
)

// curve is a brainpool curve y^2 = x^3 + a*x + b over GF(p) with prime order n.
type curve struct {
	params *elliptic.CurveParams
	oid    asn1.ObjectIdentifier
	aBig   *big.Int

	size int // byte length of p and of n (equal for all three curves)

	p, n    *bigmod.Modulus
	pMinus2 []byte // exponent for inversion mod p
	nMinus2 []byte // exponent for inversion mod n
	a, b3   *bigmod.Nat
	b       *bigmod.Nat
	one     *bigmod.Nat // 1 in Montgomery form
	gen     *point
}

var (
	bp256 = newCurve("brainpoolP256r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, p256p, p256a, p256b, p256gx, p256gy, p256n)
	bp384 = newCurve("brainpoolP384r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}, p384p, p384a, p384b, p384gx, p384gy, p384n)
	bp512 = newCurve("brainpoolP512r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, p512p, p512a, p512b, p512gx, p512gy, p512n)
)

// P256r1 returns the brainpoolP256r1 curve.
func P256r1() elliptic.Curve { return bp256 }

// P384r1 returns the brainpoolP384r1 curve.
func P384r1() elliptic.Curve { return bp384 }

// P512r1 returns the brainpoolP512r1 curve.
func P512r1() elliptic.Curve { return bp512 }

// IsBrainpool reports whether c is one of this package's curves.
func IsBrainpool(c elliptic.Curve) bool {
	_, ok := c.(*curve)
	return ok
}

// OID returns the named-curve object identifier of a brainpool curve.
func OID(c elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	cv, ok := c.(*curve)
	if !ok {
		return nil, false
	}
	return append(asn1.ObjectIdentifier(nil), cv.oid...), true
}

// CurveForOID returns the brainpool curve with the given named-curve OID.
func CurveForOID(oid asn1.ObjectIdentifier) (elliptic.Curve, bool) {
	for _, c := range []*curve{bp256, bp384, bp512} {
		if c.oid.Equal(oid) {
			return c, true
		}
	}
	return nil, false
}

func toCurve(c elliptic.Curve) (*curve, error) {
	cv, ok := c.(*curve)
	if !ok || cv == nil {
		return nil, errors.New("brainpool: not a brainpool curve")
	}
	return cv, nil
}

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("brainpool: bad constant")
	}
	return v
}

func newCurve(name string, oid asn1.ObjectIdentifier, ps, as, bs, gxs, gys, ns string) *curve {
	P, A, B, Gx, Gy, N := mustBig(ps), mustBig(as), mustBig(bs), mustBig(gxs), mustBig(gys), mustBig(ns)
	c := &curve{
		params: &elliptic.CurveParams{P: P, N: N, B: B, Gx: Gx, Gy: Gy, BitSize: P.BitLen(), Name: name},
		oid:    oid,
		aBig:   A,
		size:   (P.BitLen() + 7) / 8,
	}
	if (N.BitLen()+7)/8 != c.size {
		panic("brainpool: order and field sizes differ")
	}
	var err error
	if c.p, err = bigmod.NewModulus(hexBytes(ps)); err != nil {
		panic(err)
	}
	if c.n, err = bigmod.NewModulus(hexBytes(ns)); err != nil {
		panic(err)
	}
	c.pMinus2 = new(big.Int).Sub(P, big.NewInt(2)).Bytes()
	c.nMinus2 = new(big.Int).Sub(N, big.NewInt(2)).Bytes()
	c.a = c.feFromBig(A)
	c.b = c.feFromBig(B)
	c.b3 = c.feFromBig(new(big.Int).Mod(new(big.Int).Mul(B, big.NewInt(3)), P))
	c.one = c.feFromBig(big.NewInt(1))
	c.gen = &point{x: c.feFromBig(Gx), y: c.feFromBig(Gy), z: c.feSet(c.one)}
	return c
}

func hexBytes(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// ---------------------------------------------------------------------------
// Field elements: *bigmod.Nat of p's announced length, in Montgomery form.

func (c *curve) feNew() *bigmod.Nat { return bigmod.NewNat().ExpandFor(c.p) }

func (c *curve) feSet(a *bigmod.Nat) *bigmod.Nat { return bigmod.NewNat().Set(a) }

// feFromBytes decodes a big-endian field element of exactly c.size bytes,
// rejecting values >= p.
func (c *curve) feFromBytes(b []byte) (*bigmod.Nat, error) {
	if len(b) != c.size {
		return nil, errors.New("brainpool: bad field element length")
	}
	x, err := bigmod.NewNat().SetBytes(b, c.p)
	if err != nil {
		return nil, errors.New("brainpool: field element out of range")
	}
	return x.ToMontgomery(c.p), nil
}

func (c *curve) feFromBig(v *big.Int) *bigmod.Nat {
	x, err := c.feFromBytes(v.FillBytes(make([]byte, c.size)))
	if err != nil {
		panic(err)
	}
	return x
}

// feBytes returns the canonical big-endian encoding of a Montgomery-form
// element.
func (c *curve) feBytes(a *bigmod.Nat) []byte {
	return bigmod.NewNat().Set(a).FromMontgomery(c.p).Bytes(c.p)
}

func (c *curve) feMul(out, a, b *bigmod.Nat) { out.MontgomeryMul(a, b, c.p) }

func (c *curve) feAdd(out, a, b *bigmod.Nat) {
	t := bigmod.NewNat().Set(a)
	t.Add(b, c.p)
	out.Set(t)
}

func (c *curve) feSub(out, a, b *bigmod.Nat) {
	t := bigmod.NewNat().Set(a)
	t.Sub(b, c.p)
	out.Set(t)
}

// ---------------------------------------------------------------------------
// Points in homogeneous projective coordinates (X:Y:Z), affine (X/Z, Y/Z);
// the identity is (0:1:0).

type point struct{ x, y, z *bigmod.Nat }

func (c *curve) identity() *point {
	return &point{x: c.feNew(), y: c.feSet(c.one), z: c.feNew()}
}

func (c *curve) pointSet(q *point) *point {
	return &point{x: c.feSet(q.x), y: c.feSet(q.y), z: c.feSet(q.z)}
}

// pointSelect sets r = q if on == 1, in constant time.
func pointSelect(r *point, on uint, q *point) {
	r.x.Select(on, q.x)
	r.y.Select(on, q.y)
	r.z.Select(on, q.z)
}

// add returns p1 + p2 using the complete projective addition law for short
// Weierstrass curves with arbitrary a (Renes-Costello-Batina 2016, alg. 1).
// It is correct for every pair of inputs, including equal points and the
// identity, and runs the same operation sequence for all of them.
func (c *curve) add(p1, p2 *point) *point {
	X1, Y1, Z1 := p1.x, p1.y, p1.z
	X2, Y2, Z2 := p2.x, p2.y, p2.z
	t0, t1, t2, t3, t4, t5 := c.feNew(), c.feNew(), c.feNew(), c.feNew(), c.feNew(), c.feNew()
	X3, Y3, Z3 := c.feNew(), c.feNew(), c.feNew()

	c.feMul(t0, X1, X2)
	c.feMul(t1, Y1, Y2)
	c.feMul(t2, Z1, Z2)
	c.feAdd(t3, X1, Y1)
	c.feAdd(t4, X2, Y2)
	c.feMul(t3, t3, t4)
	c.feAdd(t4, t0, t1)
	c.feSub(t3, t3, t4)
	c.feAdd(t4, X1, Z1)
	c.feAdd(t5, X2, Z2)
	c.feMul(t4, t4, t5)
	c.feAdd(t5, t0, t2)
	c.feSub(t4, t4, t5)
	c.feAdd(t5, Y1, Z1)
	c.feAdd(X3, Y2, Z2)
	c.feMul(t5, t5, X3)
	c.feAdd(X3, t1, t2)
	c.feSub(t5, t5, X3)
	c.feMul(Z3, c.a, t4)
	c.feMul(X3, c.b3, t2)
	c.feAdd(Z3, X3, Z3)
	c.feSub(X3, t1, Z3)
	c.feAdd(Z3, t1, Z3)
	c.feMul(Y3, X3, Z3)
	c.feAdd(t1, t0, t0)
	c.feAdd(t1, t1, t0)
	c.feMul(t2, c.a, t2)
	c.feMul(t4, c.b3, t4)
	c.feAdd(t1, t1, t2)
	c.feSub(t2, t0, t2)
	c.feMul(t2, c.a, t2)
	c.feAdd(t4, t4, t2)
	c.feMul(t0, t1, t4)
	c.feAdd(Y3, Y3, t0)
	c.feMul(t0, t5, t4)
	c.feMul(X3, X3, t3)
	c.feSub(X3, X3, t0)
	c.feMul(t0, t3, t1)
	c.feMul(Z3, Z3, t5)
	c.feAdd(Z3, Z3, t0)
	return &point{x: X3, y: Y3, z: Z3}
}

// scalarMult returns k*q for a big-endian scalar k of exactly c.size bytes.
// k need not be reduced modulo n. The sequence of field operations and
// memory accesses depends only on len(k).
func (c *curve) scalarMult(q *point, k []byte) *point {
	var table [16]*point
	table[0] = c.identity()
	table[1] = c.pointSet(q)
	for i := 2; i < 16; i++ {
		table[i] = c.add(table[i-1], q)
	}
	acc := c.identity()
	sel := c.identity()
	for _, b := range k {
		for _, shift := range [2]uint{4, 0} {
			acc = c.add(acc, acc)
			acc = c.add(acc, acc)
			acc = c.add(acc, acc)
			acc = c.add(acc, acc)
			w := uint(b>>shift) & 0xf
			for i := range table {
				pointSelect(sel, bigmod.CtEq(w, uint(i)), table[i])
			}
			acc = c.add(acc, sel)
		}
	}
	return acc
}

func (c *curve) scalarBaseMult(k []byte) *point { return c.scalarMult(c.gen, k) }

// isIdentity reports (in constant time) whether q is the identity, as 0 or 1.
func (c *curve) isIdentity(q *point) uint {
	return uint(q.z.IsZero())
}

// affine returns the affine coordinates of q as big-endian bytes. q must not
// be the identity (callers check). Z is inverted by Fermat's little theorem.
func (c *curve) affine(q *point) (x, y []byte) {
	zInv := bigmod.NewNat().Set(q.z).FromMontgomery(c.p)
	zInv = bigmod.NewNat().Exp(zInv, c.pMinus2, c.p) // plain (non-Montgomery) 1/Z
	// Montgomery-multiplying X*R by the plain 1/Z yields the plain X/Z.
	xa := c.feNew()
	xa.MontgomeryMul(q.x, zInv, c.p)
	ya := c.feNew()
	ya.MontgomeryMul(q.y, zInv, c.p)
	return xa.Bytes(c.p), ya.Bytes(c.p)
}

// pointFromAffine builds a point from affine coordinates, checking that the
// coordinates are in range and satisfy the curve equation. Public data only.
func (c *curve) pointFromAffine(xb, yb []byte) (*point, error) {
	x, err := c.feFromBytes(xb)
	if err != nil {
		return nil, err
	}
	y, err := c.feFromBytes(yb)
	if err != nil {
		return nil, err
	}
	// y^2 == x^3 + a*x + b
	lhs := c.feNew()
	c.feMul(lhs, y, y)
	rhs := c.feNew()
	c.feMul(rhs, x, x)
	c.feAdd(rhs, rhs, c.a)
	c.feMul(rhs, rhs, x)
	c.feAdd(rhs, rhs, c.b)
	if lhs.Equal(rhs) != 1 {
		return nil, errors.New("brainpool: point not on curve")
	}
	return &point{x: x, y: y, z: c.feSet(c.one)}, nil
}

// pointFromUncompressed parses 0x04 || X || Y.
func (c *curve) pointFromUncompressed(b []byte) (*point, error) {
	if len(b) != 1+2*c.size || b[0] != 4 {
		return nil, errors.New("brainpool: invalid uncompressed point encoding")
	}
	return c.pointFromAffine(b[1:1+c.size], b[1+c.size:])
}

func (c *curve) marshalPoint(q *point) ([]byte, error) {
	if c.isIdentity(q) == 1 {
		return nil, errors.New("brainpool: point at infinity")
	}
	x, y := c.affine(q)
	out := make([]byte, 0, 1+2*c.size)
	out = append(out, 4)
	out = append(out, x...)
	return append(out, y...), nil
}

// scalarFromBytes decodes a private scalar of exactly c.size bytes in [1, n-1].
func (c *curve) scalarFromBytes(k []byte) (*bigmod.Nat, error) {
	if len(k) != c.size {
		return nil, errors.New("brainpool: bad scalar length")
	}
	s, err := bigmod.NewNat().SetBytes(k, c.n)
	if err != nil {
		return nil, errors.New("brainpool: scalar out of range")
	}
	if s.IsZero() == 1 {
		return nil, errors.New("brainpool: scalar is zero")
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// elliptic.Curve on math/big (variable time; public data only).

// The elliptic.Curve methods below are modelled on Go's
// crypto/elliptic/nistec.go: nistCurve (infinity as (0, 0), the IsOnCurve
// check, scalar reduction and the invalid-point panics).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
func (c *curve) Params() *elliptic.CurveParams { return c.params }

func (c *curve) bigToPoint(x, y *big.Int) (*point, bool) {
	if x.Sign() == 0 && y.Sign() == 0 {
		return c.identity(), true
	}
	if x.Sign() < 0 || y.Sign() < 0 || x.Cmp(c.params.P) >= 0 || y.Cmp(c.params.P) >= 0 {
		return nil, false
	}
	q, err := c.pointFromAffine(x.FillBytes(make([]byte, c.size)), y.FillBytes(make([]byte, c.size)))
	return q, err == nil
}

func (c *curve) pointToBig(q *point) (*big.Int, *big.Int) {
	if c.isIdentity(q) == 1 {
		return new(big.Int), new(big.Int)
	}
	x, y := c.affine(q)
	return new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)
}

func (c *curve) mustPoint(x, y *big.Int, fn string) *point {
	q, ok := c.bigToPoint(x, y)
	if !ok {
		panic("brainpool: " + fn + " was called on an invalid point")
	}
	return q
}

// IsOnCurve reports whether (x, y) is an affine point on the curve.
func (c *curve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}
	_, ok := c.bigToPoint(x, y)
	return ok
}

// Add returns (x1,y1) + (x2,y2); (0,0) stands for the point at infinity.
func (c *curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	return c.pointToBig(c.add(c.mustPoint(x1, y1, "Add"), c.mustPoint(x2, y2, "Add")))
}

// Double returns 2*(x,y).
func (c *curve) Double(x, y *big.Int) (*big.Int, *big.Int) {
	q := c.mustPoint(x, y, "Double")
	return c.pointToBig(c.add(q, q))
}

// reduceScalar reduces an arbitrary big-endian scalar modulo n and returns it
// as c.size bytes (math/big, variable time).
func (c *curve) reduceScalar(k []byte) []byte {
	v := new(big.Int).SetBytes(k)
	if v.Cmp(c.params.N) >= 0 {
		v.Mod(v, c.params.N)
	}
	return v.FillBytes(make([]byte, c.size))
}

// ScalarMult returns k*(x,y).
func (c *curve) ScalarMult(x, y *big.Int, k []byte) (*big.Int, *big.Int) {
	q := c.mustPoint(x, y, "ScalarMult")
	return c.pointToBig(c.scalarMult(q, c.reduceScalar(k)))
}

// ScalarBaseMult returns k*G.
func (c *curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return c.pointToBig(c.scalarBaseMult(c.reduceScalar(k)))
}

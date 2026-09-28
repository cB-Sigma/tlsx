// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package brainpool

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func allCurves() []elliptic.Curve { return []elliptic.Curve{P256r1(), P384r1(), P512r1()} }

// ---------------------------------------------------------------------------
// Curve definitions

func TestCurveNamesAndOIDs(t *testing.T) {
	want := []struct {
		c    elliptic.Curve
		name string
		oid  asn1.ObjectIdentifier
		bits int
	}{
		{P256r1(), "brainpoolP256r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}, 256},
		{P384r1(), "brainpoolP384r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}, 384},
		{P512r1(), "brainpoolP512r1", asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 13}, 512},
	}
	for _, w := range want {
		if got := w.c.Params().Name; got != w.name {
			t.Errorf("name %q, want %q", got, w.name)
		}
		if w.c.Params().BitSize != w.bits {
			t.Errorf("%s: BitSize %d", w.name, w.c.Params().BitSize)
		}
		if !IsBrainpool(w.c) {
			t.Errorf("%s: IsBrainpool false", w.name)
		}
		oid, ok := OID(w.c)
		if !ok || !oid.Equal(w.oid) {
			t.Errorf("%s: OID %v %v", w.name, oid, ok)
		}
		c, ok := CurveForOID(w.oid)
		if !ok || c != w.c {
			t.Errorf("%s: CurveForOID mismatch", w.name)
		}
	}
	if IsBrainpool(elliptic.P256()) {
		t.Error("P-256 reported as brainpool")
	}
	if _, ok := OID(elliptic.P256()); ok {
		t.Error("OID for P-256")
	}
	if _, ok := CurveForOID(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}); ok {
		t.Error("CurveForOID accepted prime256v1")
	}
}

func TestBasePointOnCurveAndHasOrderN(t *testing.T) {
	for _, c := range allCurves() {
		p := c.Params()
		if !c.IsOnCurve(p.Gx, p.Gy) {
			t.Fatalf("%s: G not on curve", p.Name)
		}
		if c.IsOnCurve(p.Gx, new(big.Int).Add(p.Gy, big.NewInt(1))) {
			t.Fatalf("%s: G+(0,1) on curve", p.Name)
		}
		x, y := c.ScalarBaseMult(p.N.Bytes())
		if x.Sign() != 0 || y.Sign() != 0 {
			t.Errorf("%s: n*G is not the point at infinity", p.Name)
		}
		nm1 := new(big.Int).Sub(p.N, big.NewInt(1))
		x, y = c.ScalarBaseMult(nm1.Bytes())
		if x.Cmp(p.Gx) != 0 || y.Cmp(new(big.Int).Sub(p.P, p.Gy)) != 0 {
			t.Errorf("%s: (n-1)*G != -G", p.Name)
		}
		x, y = c.ScalarMult(p.Gx, p.Gy, p.N.Bytes())
		if x.Sign() != 0 || y.Sign() != 0 {
			t.Errorf("%s: ScalarMult(G, n) not infinity", p.Name)
		}
		// (n+1)*G = G: scalars larger than n are reduced.
		np1 := new(big.Int).Add(p.N, big.NewInt(1))
		x, y = c.ScalarBaseMult(np1.Bytes())
		if x.Cmp(p.Gx) != 0 || y.Cmp(p.Gy) != 0 {
			t.Errorf("%s: (n+1)*G != G", p.Name)
		}
	}
}

// ecParameters is the explicit ECParameters structure (SEC 1) that
// `openssl ecparam -param_enc explicit -outform DER` prints.
type ecParameters struct {
	Version int
	Field   struct {
		Type  asn1.ObjectIdentifier
		Prime *big.Int
	}
	Curve struct {
		A, B []byte
		Seed asn1.BitString `asn1:"optional"`
	}
	Base     []byte
	Order    *big.Int
	Cofactor *big.Int `asn1:"optional"`
}

func TestCurveParametersMatchOpenSSL(t *testing.T) {
	ossl := opensslPath(t)
	for _, c := range allCurves() {
		name := c.Params().Name
		der := runOpenSSL(t, ossl, "", "ecparam", "-name", name, "-param_enc", "explicit", "-outform", "DER")
		var ep ecParameters
		if rest, err := asn1.Unmarshal(der, &ep); err != nil || len(rest) != 0 {
			t.Fatalf("%s: parse ECParameters: %v", name, err)
		}
		cv := c.(*curve)
		p := c.Params()
		if ep.Field.Prime.Cmp(p.P) != 0 {
			t.Errorf("%s: p differs", name)
		}
		if new(big.Int).SetBytes(ep.Curve.A).Cmp(cv.aBig) != 0 {
			t.Errorf("%s: a differs", name)
		}
		if new(big.Int).SetBytes(ep.Curve.B).Cmp(p.B) != 0 {
			t.Errorf("%s: b differs", name)
		}
		g := elliptic.Marshal(c, p.Gx, p.Gy)
		if !bytes.Equal(ep.Base, g) {
			t.Errorf("%s: G differs", name)
		}
		if ep.Order.Cmp(p.N) != 0 {
			t.Errorf("%s: n differs", name)
		}
		if ep.Cofactor != nil && ep.Cofactor.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("%s: cofactor %v", name, ep.Cofactor)
		}
	}
}

// ---------------------------------------------------------------------------
// Reference affine arithmetic on math/big (variable time, test only).

type refCurve struct{ p, a *big.Int }

func (r refCurve) add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	inf := func(x, y *big.Int) bool { return x.Sign() == 0 && y.Sign() == 0 }
	if inf(x1, y1) {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if inf(x2, y2) {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	p := r.p
	var lambda *big.Int
	if x1.Cmp(x2) == 0 {
		sum := new(big.Int).Add(y1, y2)
		if sum.Mod(sum, p).Sign() == 0 {
			return new(big.Int), new(big.Int)
		}
		num := new(big.Int).Mul(x1, x1)
		num.Mul(num, big.NewInt(3)).Add(num, r.a)
		den := new(big.Int).Lsh(y1, 1)
		lambda = num.Mul(num, den.ModInverse(den.Mod(den, p), p))
	} else {
		num := new(big.Int).Sub(y2, y1)
		den := new(big.Int).Sub(x2, x1)
		den.Mod(den, p)
		lambda = num.Mul(num, den.ModInverse(den, p))
	}
	lambda.Mod(lambda, p)
	x3 := new(big.Int).Mul(lambda, lambda)
	x3.Sub(x3, x1).Sub(x3, x2).Mod(x3, p)
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, lambda).Sub(y3, y1).Mod(y3, p)
	return x3, y3
}

func (r refCurve) mul(x, y *big.Int, k *big.Int) (*big.Int, *big.Int) {
	rx, ry := new(big.Int), new(big.Int)
	for i := k.BitLen() - 1; i >= 0; i-- {
		rx, ry = r.add(rx, ry, rx, ry)
		if k.Bit(i) == 1 {
			rx, ry = r.add(rx, ry, x, y)
		}
	}
	return rx, ry
}

func TestEllipticMethodsMatchReferenceArithmetic(t *testing.T) {
	rng := mrand.New(mrand.NewPCG(1, 2))
	for _, c := range allCurves() {
		p := c.Params()
		ref := refCurve{p: p.P, a: c.(*curve).aBig}
		randScalar := func() *big.Int {
			b := make([]byte, (p.BitSize+7)/8)
			for i := range b {
				b[i] = byte(rng.Uint32())
			}
			return new(big.Int).Mod(new(big.Int).SetBytes(b), p.N)
		}
		for i := 0; i < 8; i++ {
			k1, k2 := randScalar(), randScalar()
			x1, y1 := c.ScalarBaseMult(k1.Bytes())
			rx1, ry1 := ref.mul(p.Gx, p.Gy, k1)
			if x1.Cmp(rx1) != 0 || y1.Cmp(ry1) != 0 {
				t.Fatalf("%s: ScalarBaseMult differs from reference", p.Name)
			}
			if !c.IsOnCurve(x1, y1) {
				t.Fatalf("%s: k*G not on curve", p.Name)
			}
			x2, y2 := c.ScalarMult(x1, y1, k2.Bytes())
			rx2, ry2 := ref.mul(rx1, ry1, k2)
			if x2.Cmp(rx2) != 0 || y2.Cmp(ry2) != 0 {
				t.Fatalf("%s: ScalarMult differs from reference", p.Name)
			}
			sx, sy := c.Add(x1, y1, x2, y2)
			rsx, rsy := ref.add(rx1, ry1, rx2, ry2)
			if sx.Cmp(rsx) != 0 || sy.Cmp(rsy) != 0 {
				t.Fatalf("%s: Add differs from reference", p.Name)
			}
			dx, dy := c.Double(x1, y1)
			ex, ey := c.Add(x1, y1, x1, y1)
			rdx, rdy := ref.add(rx1, ry1, rx1, ry1)
			if dx.Cmp(rdx) != 0 || dy.Cmp(rdy) != 0 || ex.Cmp(rdx) != 0 || ey.Cmp(rdy) != 0 {
				t.Fatalf("%s: Double differs from reference", p.Name)
			}
			// P + (-P) = infinity; P + infinity = P.
			nx, ny := c.Add(x1, y1, x1, new(big.Int).Sub(p.P, y1))
			if nx.Sign() != 0 || ny.Sign() != 0 {
				t.Fatalf("%s: P + (-P) not infinity", p.Name)
			}
			ix, iy := c.Add(x1, y1, new(big.Int), new(big.Int))
			if ix.Cmp(x1) != 0 || iy.Cmp(y1) != 0 {
				t.Fatalf("%s: P + O != P", p.Name)
			}
		}
		// Scalar zero and empty scalar give infinity.
		for _, k := range [][]byte{nil, {0}, {0, 0, 0}} {
			x, y := c.ScalarBaseMult(k)
			if x.Sign() != 0 || y.Sign() != 0 {
				t.Errorf("%s: 0*G not infinity", p.Name)
			}
		}
	}
}

func TestEllipticMethodsPanicOnInvalidPoint(t *testing.T) {
	c := P256r1()
	p := c.Params()
	defer func() {
		if recover() == nil {
			t.Error("ScalarMult accepted a point that is not on the curve")
		}
	}()
	c.ScalarMult(p.Gx, new(big.Int).Add(p.Gy, big.NewInt(1)), []byte{3})
}

// ---------------------------------------------------------------------------
// ECDH: RFC 7027 Appendix A test vectors.

type ecdhVector struct {
	c                          elliptic.Curve
	dA, xA, yA, dB, xB, yB, xZ string
}

var rfc7027Vectors = []ecdhVector{
	{
		c:  P256r1(),
		dA: "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D",
		xA: "44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
		yA: "8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC",
		dB: "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3",
		xB: "8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
		yB: "990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A",
		xZ: "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B",
	},
	{
		c:  P384r1(),
		dA: "1E20F5E048A5886F1F157C74E91BDE2B98C8B52D58E5003D57053FC4B0BD65D6F15EB5D1EE1610DF870795143627D042",
		xA: "68B665DD91C195800650CDD363C625F4E742E8134667B767B1B476793588F885AB698C852D4A6E77A252D6380FCAF068",
		yA: "55BC91A39C9EC01DEE36017B7D673A931236D2F1F5C83942D049E3FA20607493E0D038FF2FD30C2AB67D15C85F7FAA59",
		dB: "032640BC6003C59260F7250C3DB58CE647F98E1260ACCE4ACDA3DD869F74E01F8BA5E0324309DB6A9831497ABAC96670",
		xB: "4D44326F269A597A5B58BBA565DA5556ED7FD9A8A9EB76C25F46DB69D19DC8CE6AD18E404B15738B2086DF37E71D1EB4",
		yB: "62D692136DE56CBE93BF5FA3188EF58BC8A3A0EC6C1E151A21038A42E9185329B5B275903D192F8D4E1F32FE9CC78C48",
		xZ: "0BD9D3A7EA0B3D519D09D8E48D0785FB744A6B355E6304BC51C229FBBCE239BBADF6403715C35D4FB2A5444F575D4F42",
	},
	{
		c:  P512r1(),
		dA: "16302FF0DBBB5A8D733DAB7141C1B45ACBC8715939677F6A56850A38BD87BD59B09E80279609FF333EB9D4C061231FB26F92EEB04982A5F1D1764CAD57665422",
		xA: "0A420517E406AAC0ACDCE90FCD71487718D3B953EFD7FBEC5F7F27E28C6149999397E91E029E06457DB2D3E640668B392C2A7E737A7F0BF04436D11640FD09FD",
		yA: "72E6882E8DB28AAD36237CD25D580DB23783961C8DC52DFA2EC138AD472A0FCEF3887CF62B623B2A87DE5C588301EA3E5FC269B373B60724F5E82A6AD147FDE7",
		dB: "230E18E1BCC88A362FA54E4EA3902009292F7F8033624FD471B5D8ACE49D12CFABBC19963DAB8E2F1EBA00BFFB29E4D72D13F2224562F405CB80503666B25429",
		xB: "9D45F66DE5D67E2E6DB6E93A59CE0BB48106097FF78A081DE781CDB31FCE8CCBAAEA8DD4320C4119F1E9CD437A2EAB3731FA9668AB268D871DEDA55A5473199F",
		yB: "2FDC313095BCDD5FB3A91636F07A959C8E86B5636A1E930E8396049CB481961D365CC11453A06C719835475B12CB52FC3C383BCE35E27EF194512B71876285FA",
		xZ: "A7927098655F1F9976FA50A9D566865DC530331846381C87256BAF3226244B76D36403C024D7BBF0AA0803EAFF405D3D24F11A9B5C0BEF679FE1454B21C4CD1F",
	},
}

func TestECDHRFC7027Vectors(t *testing.T) {
	for _, v := range rfc7027Vectors {
		name := v.c.Params().Name
		dA, dB := mustHex(t, v.dA), mustHex(t, v.dB)
		pubA := append([]byte{4}, append(mustHex(t, v.xA), mustHex(t, v.yA)...)...)
		pubB := append([]byte{4}, append(mustHex(t, v.xB), mustHex(t, v.yB)...)...)
		xZ := mustHex(t, v.xZ)

		// Public keys from the private scalars.
		for _, kp := range []struct{ d, pub []byte }{{dA, pubA}, {dB, pubB}} {
			x, y := v.c.ScalarBaseMult(kp.d)
			if got := elliptic.Marshal(v.c, x, y); !bytes.Equal(got, kp.pub) {
				t.Errorf("%s: public key mismatch", name)
			}
			k, err := NewPrivateKey(v.c, kp.d)
			if err != nil {
				t.Fatalf("%s: NewPrivateKey: %v", name, err)
			}
			pk := k.Public().(*ecdsa.PublicKey)
			if got := elliptic.Marshal(v.c, pk.X, pk.Y); !bytes.Equal(got, kp.pub) {
				t.Errorf("%s: PrivateKey.Public mismatch", name)
			}
		}

		zA, err := ECDH(v.c, dA, pubB)
		if err != nil {
			t.Fatalf("%s: ECDH A: %v", name, err)
		}
		zB, err := ECDH(v.c, dB, pubA)
		if err != nil {
			t.Fatalf("%s: ECDH B: %v", name, err)
		}
		if !bytes.Equal(zA, xZ) || !bytes.Equal(zB, xZ) {
			t.Errorf("%s: shared secret mismatch\n got %X\n     %X\nwant %X", name, zA, zB, xZ)
		}
		if len(zA) != (v.c.Params().BitSize+7)/8 {
			t.Errorf("%s: shared secret length %d", name, len(zA))
		}
	}
}

func TestECDHGeneratedKeysAgree(t *testing.T) {
	for _, c := range allCurves() {
		privA, pubA, err := GenerateECDHKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		privB, pubB, err := GenerateECDHKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		size := (c.Params().BitSize + 7) / 8
		if len(privA) != size || len(pubA) != 1+2*size || pubA[0] != 4 {
			t.Fatalf("%s: bad key sizes %d %d", c.Params().Name, len(privA), len(pubA))
		}
		zA, err := ECDH(c, privA, pubB)
		if err != nil {
			t.Fatal(err)
		}
		zB, err := ECDH(c, privB, pubA)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(zA, zB) {
			t.Errorf("%s: generated keys disagree", c.Params().Name)
		}
	}
}

func TestECDHRejectsBadInput(t *testing.T) {
	v := rfc7027Vectors[0]
	c := v.c
	p := c.Params()
	dA := mustHex(t, v.dA)
	xB, yB := mustHex(t, v.xB), mustHex(t, v.yB)
	good := append([]byte{4}, append(append([]byte{}, xB...), yB...)...)
	if _, err := ECDH(c, dA, good); err != nil {
		t.Fatalf("good point rejected: %v", err)
	}
	offCurve := bytes.Clone(good)
	offCurve[len(offCurve)-1] ^= 1
	pBytes := p.P.FillBytes(make([]byte, 32))
	xTooBig := append([]byte{4}, append(pBytes, yB...)...)
	zero := make([]byte, 65)
	zero[0] = 4
	compressed := append([]byte{2}, xB...)
	badPrefix := bytes.Clone(good)
	badPrefix[0] = 6
	for name, peer := range map[string][]byte{
		"off curve":            offCurve,
		"coordinate >= p":      xTooBig,
		"zero point":           zero,
		"infinity single byte": {0},
		"compressed":           compressed,
		"bad prefix":           badPrefix,
		"short":                good[:64],
		"long":                 append(bytes.Clone(good), 0),
		"empty":                nil,
		"P-256 generator":      elliptic.Marshal(elliptic.P256(), elliptic.P256().Params().Gx, elliptic.P256().Params().Gy),
	} {
		if _, err := ECDH(c, dA, peer); err == nil {
			t.Errorf("peer %s accepted", name)
		}
	}
	nBytes := p.N.FillBytes(make([]byte, 32))
	above := new(big.Int).Add(p.N, big.NewInt(5)).FillBytes(make([]byte, 32))
	for name, priv := range map[string][]byte{
		"zero":  make([]byte, 32),
		"n":     nBytes,
		"n+5":   above,
		"all 1": bytes.Repeat([]byte{0xff}, 32),
		"short": dA[1:],
		"long":  append([]byte{0}, dA...),
	} {
		if _, err := ECDH(c, priv, good); err == nil {
			t.Errorf("private scalar %s accepted", name)
		}
	}
	if _, err := ECDH(elliptic.P256(), dA, good); err == nil {
		t.Error("non-brainpool curve accepted")
	}
	if _, _, err := GenerateECDHKey(elliptic.P256(), rand.Reader); err == nil {
		t.Error("GenerateECDHKey accepted P-256")
	}
}

// ---------------------------------------------------------------------------
// ECDSA

func digestFor(c elliptic.Curve, msg []byte) ([]byte, crypto.Hash) {
	switch c.Params().BitSize {
	case 256:
		h := sha256.Sum256(msg)
		return h[:], crypto.SHA256
	case 384:
		h := sha512.Sum384(msg)
		return h[:], crypto.SHA384
	default:
		h := sha512.Sum512(msg)
		return h[:], crypto.SHA512
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	for _, c := range allCurves() {
		name := c.Params().Name
		k, err := GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub := k.Public().(*ecdsa.PublicKey)
		if pub.Curve != c {
			t.Fatalf("%s: public key curve %v", name, pub.Curve)
		}
		msg := []byte("brainpool " + name)
		digests := map[string][]byte{}
		h256 := sha256.Sum256(msg)
		h384 := sha512.Sum384(msg)
		h512 := sha512.Sum512(msg)
		digests["sha256"] = h256[:]
		digests["sha384"] = h384[:]
		digests["sha512"] = h512[:]
		digests["short"] = []byte{1, 2, 3}
		for dn, digest := range digests {
			for _, opts := range []crypto.SignerOpts{crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.Hash(0)} {
				sig, err := k.Sign(rand.Reader, digest, opts)
				if err != nil {
					t.Fatalf("%s/%s: Sign: %v", name, dn, err)
				}
				if !Verify(pub, digest, sig) {
					t.Fatalf("%s/%s: Verify failed", name, dn)
				}
				if !ecdsa.VerifyASN1(pub, digest, sig) {
					t.Fatalf("%s/%s: ecdsa.VerifyASN1 failed", name, dn)
				}
				bad := bytes.Clone(digest)
				bad[0] ^= 0x80
				if Verify(pub, bad, sig) || ecdsa.VerifyASN1(pub, bad, sig) {
					t.Fatalf("%s/%s: tampered digest verified", name, dn)
				}
				badSig := bytes.Clone(sig)
				badSig[len(badSig)-1] ^= 1
				if Verify(pub, digest, badSig) || ecdsa.VerifyASN1(pub, digest, badSig) {
					t.Fatalf("%s/%s: tampered signature verified", name, dn)
				}
			}
		}
		// A signature by another key does not verify.
		k2, _ := GenerateKey(c, rand.Reader)
		sig, _ := k2.Sign(rand.Reader, h256[:], crypto.SHA256)
		if Verify(pub, h256[:], sig) || ecdsa.VerifyASN1(pub, h256[:], sig) {
			t.Fatalf("%s: other key's signature verified", name)
		}
		// Signatures made through crypto/ecdsa's generic path (which uses our
		// elliptic.Curve methods) verify with Verify.
		sig, err = ecdsa.SignASN1(rand.Reader, k.ECDSA(), h256[:])
		if err != nil {
			t.Fatalf("%s: ecdsa.SignASN1: %v", name, err)
		}
		if !Verify(pub, h256[:], sig) {
			t.Fatalf("%s: signature from crypto/ecdsa rejected", name)
		}
		// Nil rand falls back to crypto/rand.
		if sig, err := k.Sign(nil, h256[:], crypto.SHA256); err != nil || !Verify(pub, h256[:], sig) {
			t.Fatalf("%s: Sign with nil rand: %v", name, err)
		}
	}
}

func TestVerifyRejectsOutOfRangeSignatures(t *testing.T) {
	c := P256r1()
	k, _ := GenerateKey(c, rand.Reader)
	pub := k.Public().(*ecdsa.PublicKey)
	digest := sha256.Sum256([]byte("x"))
	n := c.Params().N
	type sigT struct{ R, S *big.Int }
	for name, s := range map[string]sigT{
		"r=0":  {big.NewInt(0), big.NewInt(1)},
		"s=0":  {big.NewInt(1), big.NewInt(0)},
		"r=n":  {n, big.NewInt(1)},
		"s=n":  {big.NewInt(1), n},
		"r<0":  {big.NewInt(-1), big.NewInt(1)},
		"huge": {new(big.Int).Lsh(n, 10), big.NewInt(1)},
	} {
		der, _ := asn1.Marshal(s)
		if Verify(pub, digest[:], der) || ecdsa.VerifyASN1(pub, digest[:], der) {
			t.Errorf("%s accepted", name)
		}
	}
	if Verify(pub, digest[:], []byte{0x30, 0}) {
		t.Error("empty SEQUENCE accepted")
	}
	offCurve := &ecdsa.PublicKey{Curve: c, X: pub.X, Y: new(big.Int).Add(pub.Y, big.NewInt(1))}
	sig, _ := k.Sign(rand.Reader, digest[:], crypto.SHA256)
	if Verify(offCurve, digest[:], sig) {
		t.Error("off-curve public key accepted")
	}
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if Verify(&p256.PublicKey, digest[:], sig) {
		t.Error("P-256 key accepted by Verify")
	}
}

func TestNewPrivateKeyValidation(t *testing.T) {
	c := P384r1()
	n := c.Params().N
	if _, err := NewPrivateKey(c, make([]byte, 48)); err == nil {
		t.Error("zero scalar accepted")
	}
	if _, err := NewPrivateKey(c, n.FillBytes(make([]byte, 48))); err == nil {
		t.Error("scalar n accepted")
	}
	if _, err := NewPrivateKey(elliptic.P384(), []byte{1}); err == nil {
		t.Error("P-384 accepted")
	}
	// Shorter encodings are left-padded.
	k, err := NewPrivateKey(c, []byte{7})
	if err != nil {
		t.Fatal(err)
	}
	x, y := c.ScalarBaseMult([]byte{7})
	pk := k.Public().(*ecdsa.PublicKey)
	if pk.X.Cmp(x) != 0 || pk.Y.Cmp(y) != 0 {
		t.Error("public key for d=7 wrong")
	}
	ek := k.ECDSA()
	if ek.D.Cmp(big.NewInt(7)) != 0 || ek.Curve != c || ek.X.Cmp(x) != 0 {
		t.Error("ECDSA() mismatch")
	}
}

// ---------------------------------------------------------------------------
// Encodings

func TestKeyEncodingsRoundTrip(t *testing.T) {
	for _, c := range allCurves() {
		name := c.Params().Name
		k, err := GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub := k.Public().(*ecdsa.PublicKey)

		spki, err := MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("%s: MarshalPKIXPublicKey: %v", name, err)
		}
		pub2, err := ParsePKIXPublicKey(spki)
		if err != nil {
			t.Fatalf("%s: ParsePKIXPublicKey: %v", name, err)
		}
		if pub2.Curve != c || pub2.X.Cmp(pub.X) != 0 || pub2.Y.Cmp(pub.Y) != 0 {
			t.Fatalf("%s: PKIX round trip mismatch", name)
		}

		sec1, err := MarshalECPrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		for label, parse := range map[string]func() (*PrivateKey, error){
			"sec1":         func() (*PrivateKey, error) { return ParseECPrivateKey(sec1) },
			"pkcs8":        func() (*PrivateKey, error) { return ParsePKCS8PrivateKey(pkcs8) },
			"pkcs8 via ec": func() (*PrivateKey, error) { return ParseECPrivateKey(pkcs8) },
		} {
			k2, err := parse()
			if err != nil {
				t.Fatalf("%s/%s: %v", name, label, err)
			}
			if k2.ECDSA().D.Cmp(k.ECDSA().D) != 0 || k2.ECDSA().X.Cmp(pub.X) != 0 {
				t.Fatalf("%s/%s: key mismatch", name, label)
			}
		}
		if _, err := ParsePKCS8PrivateKey(sec1); err == nil {
			t.Errorf("%s: SEC1 accepted as PKCS#8", name)
		}
		// Corruptions.
		badSPKI := bytes.Clone(spki)
		badSPKI[len(badSPKI)-1] ^= 1
		if _, err := ParsePKIXPublicKey(badSPKI); err == nil {
			t.Errorf("%s: off-curve SPKI accepted", name)
		}
		if _, err := ParsePKIXPublicKey(append(bytes.Clone(spki), 0)); err == nil {
			t.Errorf("%s: SPKI with trailing data accepted", name)
		}
	}

	// Other curves are refused.
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if _, err := MarshalPKIXPublicKey(&p256.PublicKey); err == nil {
		t.Error("MarshalPKIXPublicKey accepted P-256")
	}
	spki, _ := x509.MarshalPKIXPublicKey(&p256.PublicKey)
	if _, err := ParsePKIXPublicKey(spki); err == nil {
		t.Error("ParsePKIXPublicKey accepted P-256")
	}
	sec1, _ := x509.MarshalECPrivateKey(p256)
	if _, err := ParseECPrivateKey(sec1); err == nil {
		t.Error("ParseECPrivateKey accepted P-256")
	}
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(p256)
	if _, err := ParsePKCS8PrivateKey(pkcs8); err == nil {
		t.Error("ParsePKCS8PrivateKey accepted P-256")
	}
}

// ---------------------------------------------------------------------------
// Certificates

var serialCounter int64 = 100

func certTemplate(cn string, isCA bool) *x509.Certificate {
	serialCounter++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serialCounter),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"tlsx test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.BasicConstraintsValid = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		tmpl.DNSNames = []string{cn}
	}
	return tmpl
}

type chain struct {
	caDER, leafDER []byte
	caKey          crypto.Signer
	leafKey        crypto.Signer
}

func makeChain(t *testing.T, caKey, leafKey crypto.Signer) chain {
	t.Helper()
	caTmpl := certTemplate("Brainpool Test CA", true)
	caDER, err := CreateCertificate(rand.Reader, caTmpl, caTmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate CA: %v", err)
	}
	ca, err := ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("ParseCertificate CA: %v", err)
	}
	leafDER, err := CreateCertificate(rand.Reader, certTemplate("leaf.example", false), ca, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("CreateCertificate leaf: %v", err)
	}
	return chain{caDER: caDER, leafDER: leafDER, caKey: caKey, leafKey: leafKey}
}

func verifyChain(t *testing.T, ch chain) {
	t.Helper()
	ca, err := ParseCertificate(ch.caDER)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	leaf, err := ParseCertificate(ch.leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	for _, c := range []*x509.Certificate{ca, leaf} {
		if c.PublicKeyAlgorithm != x509.ECDSA {
			t.Errorf("PublicKeyAlgorithm %v", c.PublicKeyAlgorithm)
		}
		if !bytes.Equal(c.Raw, map[bool][]byte{true: ch.caDER, false: ch.leafDER}[c == ca]) {
			t.Error("Raw not restored")
		}
	}
	if !publicKeysEqual(leaf.PublicKey, ch.leafKey.Public()) {
		t.Error("leaf public key mismatch")
	}
	if !publicKeysEqual(ca.PublicKey, ch.caKey.Public()) {
		t.Error("CA public key mismatch")
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CheckSignatureFrom: %v", err)
	}
	if err := ca.CheckSignatureFrom(ca); err != nil {
		t.Fatalf("CA self-signature: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "leaf.example"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(chains) != 1 || len(chains[0]) != 2 {
		t.Fatalf("unexpected chains %v", chains)
	}
	// A tampered leaf must not verify.
	bad := bytes.Clone(ch.leafDER)
	bad[len(bad)-1] ^= 1
	if badLeaf, err := ParseCertificate(bad); err == nil {
		if _, err := badLeaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "leaf.example"}); err == nil {
			t.Fatal("tampered leaf verified")
		}
	}
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	ea, ok1 := a.(*ecdsa.PublicKey)
	eb, ok2 := b.(*ecdsa.PublicKey)
	if !ok1 || !ok2 {
		return false
	}
	return ea.Curve.Params().Name == eb.Curve.Params().Name && ea.X.Cmp(eb.X) == 0 && ea.Y.Cmp(eb.Y) == 0
}

func TestCertificateChains(t *testing.T) {
	bp256, _ := GenerateKey(P256r1(), rand.Reader)
	bp384, _ := GenerateKey(P384r1(), rand.Reader)
	bp512, _ := GenerateKey(P512r1(), rand.Reader)
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cases := []struct {
		name     string
		ca, leaf crypto.Signer
	}{
		{"bp384 CA, bp256 leaf", bp384, bp256},
		{"bp256 CA, bp256 leaf", bp256, mustKey(t, P256r1())},
		{"bp512 CA, bp384 leaf", bp512, bp384},
		{"P-256 CA, bp256 leaf", p256, bp256},
		{"bp384 CA, P-256 leaf", bp384, mustP256(t)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := makeChain(t, tc.ca, tc.leaf)
			if !IsBrainpoolCertificate(ch.leafDER) == isBP(tc.leaf) {
				t.Errorf("IsBrainpoolCertificate(leaf) wrong")
			}
			verifyChain(t, ch)
		})
	}
	// Signature algorithm follows the brainpool CA key size.
	for _, tc := range []struct {
		k    crypto.Signer
		want x509.SignatureAlgorithm
	}{{bp256, x509.ECDSAWithSHA256}, {bp384, x509.ECDSAWithSHA384}, {bp512, x509.ECDSAWithSHA512}} {
		ch := makeChain(t, tc.k, bp256)
		leaf, err := ParseCertificate(ch.leafDER)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.SignatureAlgorithm != tc.want {
			t.Errorf("signature algorithm %v, want %v", leaf.SignatureAlgorithm, tc.want)
		}
	}
	// Ordinary certificates pass straight through.
	ch := makeChain(t, p256, mustP256(t))
	if IsBrainpoolCertificate(ch.leafDER) {
		t.Error("P-256 leaf reported as brainpool")
	}
	verifyChain(t, ch)
	if _, err := ParseCertificate([]byte{0x30, 0x03, 0x02, 0x01, 0x01}); err == nil {
		t.Error("garbage parsed as certificate")
	}
}

func isBP(s crypto.Signer) bool {
	pk, ok := s.Public().(*ecdsa.PublicKey)
	return ok && IsBrainpool(pk.Curve)
}

func mustKey(t *testing.T, c elliptic.Curve) *PrivateKey {
	t.Helper()
	k, err := GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// ---------------------------------------------------------------------------
// OpenSSL cross-checks (skipped when openssl is not installed).

func opensslPath(t *testing.T) string {
	t.Helper()
	if os.Getenv("TLSX_SKIP_INTEROP") != "" {
		t.Skip("TLSX_SKIP_INTEROP is set")
	}
	if _, err := os.Stat("/opt/homebrew/bin/openssl"); err == nil {
		return "/opt/homebrew/bin/openssl"
	}
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed")
	}
	return p
}

func runOpenSSL(t *testing.T, ossl, dir string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ossl, args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("openssl %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	return out
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readPEM(t *testing.T, path, typ string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for {
		var b *pem.Block
		b, raw = pem.Decode(raw)
		if b == nil {
			t.Fatalf("%s: no %s block", path, typ)
		}
		if b.Type == typ {
			return b.Bytes
		}
	}
}

func TestOpenSSLSignaturesBothWays(t *testing.T) {
	ossl := opensslPath(t)
	dir := t.TempDir()
	msg := filepath.Join(dir, "msg.bin")
	if err := os.WriteFile(msg, []byte("oms mode 13 brainpool cross-check"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range allCurves() {
		name := c.Params().Name
		_, h := digestFor(c, nil)
		dgst := map[crypto.Hash]string{crypto.SHA256: "-sha256", crypto.SHA384: "-sha384", crypto.SHA512: "-sha512"}[h]
		m, _ := os.ReadFile(msg)
		digest, _ := digestFor(c, m)

		// (1a) OpenSSL key (PKCS#8 and SEC1), OpenSSL signs, we verify.
		key := filepath.Join(dir, name+".key")
		runOpenSSL(t, ossl, dir, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:"+name,
			"-pkeyopt", "ec_param_enc:named_curve", "-out", key)
		sec1 := filepath.Join(dir, name+".sec1")
		runOpenSSL(t, ossl, dir, "ec", "-in", key, "-out", sec1)
		pubPEM := filepath.Join(dir, name+".pub")
		runOpenSSL(t, ossl, dir, "pkey", "-in", key, "-pubout", "-out", pubPEM)
		sigFile := filepath.Join(dir, name+".sig")
		runOpenSSL(t, ossl, dir, "dgst", dgst, "-sign", key, "-out", sigFile, msg)

		pub, err := ParsePKIXPublicKey(readPEM(t, pubPEM, "PUBLIC KEY"))
		if err != nil {
			t.Fatalf("%s: parse OpenSSL public key: %v", name, err)
		}
		sig, _ := os.ReadFile(sigFile)
		if !Verify(pub, digest, sig) {
			t.Errorf("%s: OpenSSL signature rejected by Verify", name)
		}
		if !ecdsa.VerifyASN1(pub, digest, sig) {
			t.Errorf("%s: OpenSSL signature rejected by ecdsa.VerifyASN1", name)
		}
		k8, err := ParsePKCS8PrivateKey(readPEM(t, key, "PRIVATE KEY"))
		if err != nil {
			t.Fatalf("%s: parse OpenSSL PKCS#8 key: %v", name, err)
		}
		k1, err := ParseECPrivateKey(readPEM(t, sec1, "EC PRIVATE KEY"))
		if err != nil {
			t.Fatalf("%s: parse OpenSSL SEC1 key: %v", name, err)
		}
		if !publicKeysEqual(k8.Public(), pub) || !publicKeysEqual(k1.Public(), pub) {
			t.Errorf("%s: parsed OpenSSL private keys do not match public key", name)
		}

		// (1b) We sign, OpenSSL verifies with our PKIX public key.
		ours, _ := GenerateKey(c, rand.Reader)
		spki, err := MarshalPKIXPublicKey(ours.Public().(*ecdsa.PublicKey))
		if err != nil {
			t.Fatal(err)
		}
		ourPub := filepath.Join(dir, name+".ours.pub")
		writePEM(t, ourPub, "PUBLIC KEY", spki)
		ourSig, err := ours.Sign(rand.Reader, digest, h)
		if err != nil {
			t.Fatal(err)
		}
		ourSigFile := filepath.Join(dir, name+".ours.sig")
		if err := os.WriteFile(ourSigFile, ourSig, 0o600); err != nil {
			t.Fatal(err)
		}
		out := runOpenSSL(t, ossl, dir, "dgst", dgst, "-verify", ourPub, "-signature", ourSigFile, msg)
		if !strings.Contains(string(out), "Verified OK") {
			t.Errorf("%s: OpenSSL did not verify our signature: %s", name, out)
		}

		// Keys we write parse in OpenSSL and give the same public key.
		for label, der := range map[string]struct {
			typ string
			fn  func(*PrivateKey) ([]byte, error)
		}{
			"sec1":  {"EC PRIVATE KEY", MarshalECPrivateKey},
			"pkcs8": {"PRIVATE KEY", MarshalPKCS8PrivateKey},
		} {
			b, err := der.fn(ours)
			if err != nil {
				t.Fatal(err)
			}
			f := filepath.Join(dir, name+".ours."+label)
			writePEM(t, f, der.typ, b)
			pubOut := runOpenSSL(t, ossl, dir, "pkey", "-in", f, "-pubout", "-outform", "DER")
			if !bytes.Equal(pubOut, spki) {
				t.Errorf("%s/%s: OpenSSL derives a different public key", name, label)
			}
			runOpenSSL(t, ossl, dir, "pkey", "-in", f, "-check", "-noout")
		}
	}
}

func TestOpenSSLECDH(t *testing.T) {
	ossl := opensslPath(t)
	dir := t.TempDir()
	for _, c := range allCurves() {
		name := c.Params().Name
		key := filepath.Join(dir, name+".key")
		runOpenSSL(t, ossl, dir, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:"+name,
			"-pkeyopt", "ec_param_enc:named_curve", "-out", key)
		theirPub, err := ParsePKIXPublicKey(runOpenSSL(t, ossl, dir, "pkey", "-in", key, "-pubout", "-outform", "DER"))
		if err != nil {
			t.Fatal(err)
		}
		priv, pub, err := GenerateECDHKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x, y := elliptic.Unmarshal(c, pub)
		spki, err := MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: c, X: x, Y: y})
		if err != nil {
			t.Fatal(err)
		}
		ourPub := filepath.Join(dir, name+".ours.pub")
		writePEM(t, ourPub, "PUBLIC KEY", spki)
		zFile := filepath.Join(dir, name+".z")
		runOpenSSL(t, ossl, dir, "pkeyutl", "-derive", "-inkey", key, "-peerkey", ourPub, "-out", zFile)
		want, _ := os.ReadFile(zFile)
		got, err := ECDH(c, priv, elliptic.Marshal(c, theirPub.X, theirPub.Y))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: ECDH differs from OpenSSL\n got %X\nwant %X", name, got, want)
		}
	}
}

func TestOpenSSLCertificates(t *testing.T) {
	ossl := opensslPath(t)
	dir := t.TempDir()
	path := func(n string) string { return filepath.Join(dir, n) }

	// (3a) OpenSSL makes a brainpoolP384r1 CA and a brainpoolP256r1 leaf.
	runOpenSSL(t, ossl, dir, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP384r1",
		"-pkeyopt", "ec_param_enc:named_curve", "-out", path("ca.key"))
	runOpenSSL(t, ossl, dir, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:brainpoolP256r1",
		"-pkeyopt", "ec_param_enc:named_curve", "-out", path("leaf.key"))
	runOpenSSL(t, ossl, dir, "req", "-x509", "-new", "-key", path("ca.key"), "-subj", "/CN=OpenSSL Brainpool CA",
		"-days", "2", "-sha384", "-addext", "basicConstraints=critical,CA:TRUE",
		"-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", path("ca.crt"))
	runOpenSSL(t, ossl, dir, "req", "-new", "-key", path("leaf.key"), "-subj", "/CN=leaf.example", "-out", path("leaf.csr"))
	if err := os.WriteFile(path("leaf.ext"), []byte("subjectAltName=DNS:leaf.example\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runOpenSSL(t, ossl, dir, "x509", "-req", "-in", path("leaf.csr"), "-CA", path("ca.crt"), "-CAkey", path("ca.key"),
		"-set_serial", "7", "-days", "2", "-sha256", "-extfile", path("leaf.ext"), "-out", path("leaf.crt"))

	caDER := readPEM(t, path("ca.crt"), "CERTIFICATE")
	leafDER := readPEM(t, path("leaf.crt"), "CERTIFICATE")
	if !IsBrainpoolCertificate(caDER) || !IsBrainpoolCertificate(leafDER) {
		t.Fatal("IsBrainpoolCertificate false for OpenSSL brainpool certificates")
	}
	if _, err := x509.ParseCertificate(leafDER); err == nil {
		t.Log("note: crypto/x509 parsed a brainpool certificate by itself")
	}
	caKey, err := ParsePKCS8PrivateKey(readPEM(t, path("ca.key"), "PRIVATE KEY"))
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ParsePKCS8PrivateKey(readPEM(t, path("leaf.key"), "PRIVATE KEY"))
	if err != nil {
		t.Fatal(err)
	}
	verifyChain(t, chain{caDER: caDER, leafDER: leafDER, caKey: caKey, leafKey: leafKey})
	leaf, _ := ParseCertificate(leafDER)
	if leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || leaf.Subject.CommonName != "leaf.example" {
		t.Errorf("leaf fields: %v %q", leaf.SignatureAlgorithm, leaf.Subject.CommonName)
	}

	// (3b) Our CreateCertificate output is accepted by openssl verify, for a
	// brainpool CA and leaf, and for a leaf issued by the OpenSSL CA.
	ourCA, _ := GenerateKey(P512r1(), rand.Reader)
	ourLeaf, _ := GenerateKey(P256r1(), rand.Reader)
	ch := makeChain(t, ourCA, ourLeaf)
	writePEM(t, path("our-ca.crt"), "CERTIFICATE", ch.caDER)
	writePEM(t, path("our-leaf.crt"), "CERTIFICATE", ch.leafDER)
	out := runOpenSSL(t, ossl, dir, "verify", "-CAfile", path("our-ca.crt"), path("our-leaf.crt"))
	if !strings.Contains(string(out), ": OK") {
		t.Errorf("openssl verify: %s", out)
	}
	osslCA, _ := ParseCertificate(caDER)
	leaf2, err := CreateCertificate(rand.Reader, certTemplate("leaf.example", false), osslCA, ourLeaf.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, path("leaf2.crt"), "CERTIFICATE", leaf2)
	out = runOpenSSL(t, ossl, dir, "verify", "-CAfile", path("ca.crt"), path("leaf2.crt"))
	if !strings.Contains(string(out), ": OK") {
		t.Errorf("openssl verify leaf2: %s", out)
	}
	verifyChain(t, chain{caDER: caDER, leafDER: leaf2, caKey: caKey, leafKey: ourLeaf})
}

// ---------------------------------------------------------------------------
// Benchmarks

func BenchmarkECDHP256r1(b *testing.B) {
	c := P256r1()
	priv, _, _ := GenerateECDHKey(c, rand.Reader)
	_, peer, _ := GenerateECDHKey(c, rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ECDH(c, priv, peer); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignP256r1(b *testing.B) {
	k, _ := GenerateKey(P256r1(), rand.Reader)
	digest := sha256.Sum256([]byte("bench"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := k.Sign(rand.Reader, digest[:], crypto.SHA256); err != nil {
			b.Fatal(err)
		}
	}
}

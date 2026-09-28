// Copyright 2026 Abhinav Gautam. Use of this source code is governed
// by the BSD-style licence in the LICENSE file.
// Portions Copyright The Go Authors (BSD-3-Clause; see NOTICE)

package ccm

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// unhex is like Go's decodeHex test helper (crypto/cipher/gcm_test.go).
// Copyright The Go Authors, BSD-3-Clause; see NOTICE.
func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRFC3610Vectors runs the 24 packet vectors of RFC 3610 section 8 (the
// first header octets are the additional data, the rest the payload).
func TestRFC3610Vectors(t *testing.T) {
	b, err := os.ReadFile("testdata/rfc3610.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []struct {
		Vector, Header, Tag       int
		Key, Nonce, Input, Output string
	}
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) != 24 {
		t.Fatalf("%d vectors", len(vs))
	}
	for _, v := range vs {
		blk, err := aes.NewCipher(unhex(t, v.Key))
		if err != nil {
			t.Fatal(err)
		}
		nonce, in, want := unhex(t, v.Nonce), unhex(t, v.Input), unhex(t, v.Output)
		a, err := New(blk, len(nonce), v.Tag)
		if err != nil {
			t.Fatal(err)
		}
		ad, plain := in[:v.Header], in[v.Header:]
		got := a.Seal(append([]byte(nil), ad...), nonce, plain, ad)
		if !bytes.Equal(got, want) {
			t.Fatalf("vector %d: sealed %x, want %x", v.Vector, got, want)
		}
		back, err := a.Open(nil, nonce, want[v.Header:], ad)
		if err != nil || !bytes.Equal(back, plain) {
			t.Fatalf("vector %d: open %x %v", v.Vector, back, err)
		}
		bad := append([]byte(nil), want[v.Header:]...)
		bad[len(bad)-1] ^= 1
		if _, err := a.Open(nil, nonce, bad, ad); err != ErrOpen {
			t.Fatalf("vector %d: a changed tag opened (%v)", v.Vector, err)
		}
		if _, err := a.Open(nil, nonce, want[v.Header:], append([]byte{1}, ad...)); err != ErrOpen {
			t.Fatalf("vector %d: changed additional data opened", v.Vector)
		}
	}
}

// TestTLSShape checks the TLS 1.3 shape (12-byte nonce, 16-byte tag)
// against a value from an independent implementation (Python
// cryptography's AESCCM) and in-place sealing and opening.
func TestTLSShape(t *testing.T) {
	blk, _ := aes.NewCipher(unhex(t, "000102030405060708090a0b0c0d0e0f"))
	a, err := New(blk, 12, 16)
	if err != nil {
		t.Fatal(err)
	}
	nonce := unhex(t, "6465666768696a6b6c6d6e6f")
	ad := unhex(t, "746c733133207265636f726420686561646572")
	plain := unhex(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324")
	want := unhex(t, "a0489522b91efde0d8f1b0e2b1ccaa456e2886e09148e4e13450a76f077873e8348033b31a1e839a523251f720bf1c3539f0802a51")
	buf := make([]byte, len(plain), len(plain)+16)
	copy(buf, plain)
	got := a.Seal(buf[:0], nonce, buf, ad)
	if !bytes.Equal(got, want) {
		t.Fatalf("sealed %x", got)
	}
	back, err := a.Open(got[:0], nonce, got, ad)
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatalf("open: %x %v", back, err)
	}
	for _, bad := range [][2]int{{6, 16}, {14, 16}, {12, 3}, {12, 17}, {12, 5}} {
		if _, err := New(blk, bad[0], bad[1]); err == nil {
			t.Errorf("nonce %d tag %d accepted", bad[0], bad[1])
		}
	}
	if _, err := a.Open(nil, nonce, make([]byte, 15), ad); err != ErrOpen {
		t.Error("short ciphertext opened")
	}
}

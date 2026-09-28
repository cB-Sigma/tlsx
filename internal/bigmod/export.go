// Copyright 2026 Abhinav Gautam. Use of this source code is governed by
// the BSD-style licence in the LICENSE file.

package bigmod

// Exported helpers used by sibling packages (the brainpool curves) that need
// Montgomery-domain arithmetic and constant-time selection. They are thin
// wrappers around the unexported primitives in nat.go.

// Set assigns x = y, resizing x to the announced length of y. Unlike the
// unexported set, it is safe when x and y are the same Nat.
func (x *Nat) Set(y *Nat) *Nat {
	if x == y {
		return x
	}
	return x.set(y)
}

// Select assigns x = y if on is 1 and leaves x unchanged if on is 0, in
// constant time. on must be 0 or 1. Both operands must have the same announced
// length.
func (x *Nat) Select(on uint, y *Nat) *Nat {
	return x.assign(choice(on&1), y)
}

// MontgomeryMul sets x = a * b / R mod m, where R = 2^(W * limbs(m)). a and b
// must be reduced modulo m and have the announced length of m; x may alias
// either of them. m must be odd.
func (x *Nat) MontgomeryMul(a, b *Nat, m *Modulus) *Nat {
	return x.montgomeryMul(a, b, m)
}

// ToMontgomery sets x = x * R mod m. x must be reduced modulo m and have the
// announced length of m.
func (x *Nat) ToMontgomery(m *Modulus) *Nat {
	return x.montgomeryRepresentation(m)
}

// FromMontgomery sets x = x / R mod m. x must be reduced modulo m and have the
// announced length of m.
func (x *Nat) FromMontgomery(m *Modulus) *Nat {
	return x.montgomeryReduction(m)
}

// CtEq returns 1 if x == y and 0 otherwise, in constant time.
func CtEq(x, y uint) uint {
	return uint(ctEq(x, y))
}

// Package big is my custom bignum library for lolz. Unlike Go's math/big library, I
// only care about 64-bit architectures which enables some simplifications.
//
// Unfun fact: I spent a ridiculous amount of time getting this piece of code to be
// correct -- roughly as much time writing this as I did solving all the Cryptopals levels
// combined! Writing (and debugging) a complete bignum library turns out to be a bit of an
// undertaking.
//
// This library's API is different from math/big. It doesn't require the library user to
// pre-allocate big.Int variables which makes for subjectively cleaner coder.
//
// For now, the internal representation is 4-bit arrays. This makes it easier to write
// comprehensive tests which cover various edge cases.
package big

import (
	originalBig "math/big"
)

type Int struct {
	v   []uint8 // less significant value is stored at offset 0
	neg bool
}

var Zero = NewInt(0)
var One = NewInt(1)
var W = 4                   // number of bits per array element
var M = uint8((1 << W) - 1) // mask

func NewInt(v int64) *Int {
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	r := &Int{
		v:   []uint8{},
		neg: neg,
	}

	for {
		r.v = append(r.v, uint8(v)&M)
		v = v >> W
		if v == 0 {
			break
		}
	}

	return r
}

// FromBytes interprets v as the bytes of a big-endian unsigned integer.
func FromBytes(v []byte) *Int {
	// calculate how many array elements we'll need
	//	size := (len(v) + utils.Remaining(len(v), 8)) / 8
	size := len(v) * 2
	r := &Int{
		v: make([]uint8, 0, size),
	}

	for i := len(v) - 1; i >= 0; i-- {
		bottom := v[i] & M
		r.v = append(r.v, bottom)
		top := (v[i] >> W) & M
		r.v = append(r.v, top)
	}

	r.normalize()

	// t := uint64(0)
	// j := 0
	// for i := len(v) - 1; i >= 0; i-- {
	// 	t = t | (uint64(v[i]) << (8 * j))
	// 	j++
	// 	if j == 8 {
	// 		r.v = append(r.v, t)
	// 		j = 0
	// 		t = 0
	// 	}
	// }
	// if t != 0 {
	// 	r.v = append(r.v, t)
	// }

	return r
}

// Bytes returns the absolute value of v1 as a big-endian byte slice.
func (v1 *Int) Bytes() []byte {
	// calculate how many array elements we'll need
	t := v1.v
	if len(t)%2 == 1 {
		t = append(t, 0)
	}

	size := len(t) / 2
	r := make([]byte, 0, size)

	for i := len(t) - 1; i >= 0; i -= 2 {
		tt := (t[i] << W) | t[i-1]
		r = append(r, tt)
	}

	//	r := make([]byte, 0, len(v1.v)*8)
	// leadingZero := true
	// for i := len(v1.v) - 1; i >= 0; i-- {
	// 	for j := 7; j >= 0; j-- {
	// 		t := v1.v[i] >> (8 * j)
	// 		if leadingZero {
	// 			if t == 0 {
	// 				continue
	// 			}
	// 			leadingZero = false
	// 		}
	// 		r = append(r, byte(t))
	// 	}
	// }
	if len(r) == 0 {
		r = append(r, 0x00)
	}
	return r
}

// IsZero returns true if v1 is zero.
func (v1 *Int) IsZero() bool {
	for i := 0; i < len(v1.v); i++ {
		if v1.v[i] != 0 {
			return false
		}
	}
	return true
}

// String converts value to its decimal representation.
func (v1 *Int) String() string {
	t := &originalBig.Int{}
	t.SetBytes(v1.Bytes())
	if v1.neg {
		t.Neg(t)
	}
	return t.String()
	// t1 := v1.clone()
	// ten := NewInt(10)
	// s := ""
	// for !t1.IsZero() {
	// 	var r *Int
	// 	t1, r = t1.Div(ten)
	// 	s = fmt.Sprintf("%d%s", r.v[0], s)
	// }
	// if s == "" {
	// 	s = "0"
	// }
	// return s
}

// Msb returns the offset of the most significant bit. Returns 0 if v1 is 0.
// Note: I should have probably just implemented BitLen?
func (v1 *Int) Msb() int {
	for i := len(v1.v) - 1; i >= 0; i-- {
		for j := (W - 1); j >= 0; j-- {
			if (v1.v[i]>>j)&1 == 1 {
				return i*W + j
			}
		}
	}
	return 0
}

// // Root from https://rosettacode.org/wiki/Integer_roots#big.Int
// func Root(N int, xx *Int) *Int {
// 	xx2 := &originalBig.Int{}
// 	xx2.SetBytes(xx.Bytes())

// 	var x, Δr originalBig.Int
// 	nn := originalBig.NewInt(int64(N))
// 	for r := originalBig.NewInt(1); ; {
// 		x.Set(xx2)
// 		for i := 1; i < N; i++ {
// 			x.Quo(&x, r)
// 		}
// 		// big.Quo performs Go-like truncated division and would allow direct
// 		// translation of the int-based solution, but package big also provides
// 		// Div which performs Euclidean rather than truncated division.
// 		// This gives the desired result for negative x so the int-based
// 		// correction is no longer needed and the code here can more directly
// 		// follow the Wikipedia article.
// 		Δr.Div(x.Sub(&x, r), nn)
// 		if len(Δr.Bits()) == 0 {
// 			return FromBytes(r.Bytes())
// 		}
// 		r.Add(r, &Δr)
// 	}
// }

// normalize() removes leading zeros and drops the neg
// sign if the result is zero.
func (v1 *Int) normalize() {
	// drop leading zeros
	leadingZeros := 0
	for i := len(v1.v) - 1; i > 0; i-- {
		if v1.v[i] == 0 {
			leadingZeros++
		} else {
			break
		}
	}
	v1.v = v1.v[0 : len(v1.v)-leadingZeros]

	// convert -0 to 0.
	if len(v1.v) == 1 && v1.v[0] == 0 {
		v1.neg = false
	}
}

func (v1 *Int) at(offset int) uint8 {
	if offset >= len(v1.v) {
		return 0
	}
	return v1.v[offset]
}

func (v1 *Int) clone() *Int {
	r := &Int{
		v:   make([]uint8, len(v1.v)),
		neg: v1.neg,
	}
	copy(r.v, v1.v)
	return r
}

// shiftLeft is private because it mutates v1
// TODO: deal with unnecessary leading 0s
func (v1 *Int) shiftLeft() {
	if v1 == One || v1 == Zero {
		panic("accidentally mutating One or Zero")
	}

	// check if we need to add an element to the array.
	if len(v1.v) == 0 {
		v1.v = append(v1.v, 0)
	} else if v1.at(len(v1.v)-1)>>(W-1) == 1 {
		v1.v = append(v1.v, 0)
	}
	carry := uint8(0)
	for i := 0; i < len(v1.v); i++ {
		nextCarry := (v1.at(i) >> (W - 1)) & 1
		v1.v[i] = ((v1.v[i] << 1) & M) | carry
		carry = nextCarry
	}
}

// shiftLeftBy is private because it mutates v1. We have to be careful not to mutate
// Zero and One as those are meant to be constants.
// TODO: implement a more efficient version of this function:
//   - shifting by multiples of 64 can be done by appending zeros to the underlying buffer.
//   - shifting by n for n<64 can be done by grabbing n bits at a time and iterating over the
//     the underlying buffer only once.
//   - shifting by an arbitrary n can be done by first shifting by n%64 and then shifting by
//     n/64.
func (v1 *Int) shiftLeftBy(n int) {
	if v1 == One || v1 == Zero {
		panic("accidentally mutating One or Zero")
	}

	for i := 0; i < n; i++ {
		v1.shiftLeft()
	}
}

// shiftRight is private because it mutates v1.
func (v1 *Int) shiftRight() {
	if v1 == One || v1 == Zero {
		panic("accidentally mutating One or Zero")
	}

	carry := uint8(0)
	if len(v1.v) > 1 {
		t := v1.at(len(v1.v) - 1)
		if t == 0 || t == 1 {
			v1.v = v1.v[0 : len(v1.v)-1]
			carry = t << (W - 1)
		}
	}
	for i := len(v1.v) - 1; i >= 0; i-- {
		nextCarry := (v1.at(i) & 1) << (W - 1)
		v1.v[i] = ((v1.v[i] >> 1) & M) | carry
		carry = nextCarry
	}
}

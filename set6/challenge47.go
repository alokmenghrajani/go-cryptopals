package set6

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/rsa"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs1_5"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

var twoB *big.Int
var threeB *big.Int
var threeBMinusOne *big.Int
var oracleCalled = 0

type Interval struct {
	low, high *big.Int
	size      *big.Int
}

func Challenge47(rng *rng.Rng) {
	utils.PrintTitle(6, 47)

	keySize := 256
	keySizeBytes := keySize / 8
	pubKey, privKey := rsa.GenerateKeyPair(rng, keySize)
	fmt.Printf("n: %d\n", pubKey.N)
	fmt.Printf("e: %d\n", pubKey.E)

	shortPlaintext := "kick it, CC"
	shortPlaintextPadded := pkcs1_5.Pad(rng, []byte(shortPlaintext), keySizeBytes)
	ciphertextBytes := pubKey.Encrypt([]byte(shortPlaintextPadded))
	ciphertext := bigutils.FromBytes(ciphertextBytes)
	fmt.Printf("ciphertext: %d\n", ciphertext)

	twoB = big.NewInt(0x02)
	twoB.Lsh(twoB, uint(keySizeBytes-2)*8)

	threeB = big.NewInt(0x03)
	threeB.Lsh(threeB, uint(keySizeBytes-2)*8)
	threeBMinusOne = &big.Int{}
	threeBMinusOne.Sub(threeB, bigutils.One)

	// find s
	s := step2a(pubKey, privKey, keySizeBytes, ciphertext, ceil(pubKey.N, threeB))
	m := intervalAppend([]Interval{}, twoB, threeBMinusOne)
	m = step3(pubKey, s, m)

	for {
		if len(m) == 0 {
			panic("Failed to find a solution.")
		}

		if len(m) == 1 {
			if m[0].size.Cmp(bigutils.One) == 0 {
				fmt.Printf("Found solution after %d calls to oracle.\n", oracleCalled)

				m[0].low.Mod(m[0].low, pubKey.N)
				bytes := append([]byte{0x00}, m[0].low.Bytes()...)
				msg, err := pkcs1_5.Unpad(bytes, keySizeBytes)
				utils.PanicOnErr(err)
				fmt.Printf("%q\n", msg)
				if string(msg) != shortPlaintext {
					panic("Failed to decrypt correct message.")
				}
				break
			}
			s = step2c(pubKey, privKey, keySizeBytes, ciphertext, m[0], s)
		}

		if len(m) > 1 {
			s.Add(s, bigutils.One)
			s = step2a(pubKey, privKey, keySizeBytes, ciphertext, s)
		}

		// compute intervals
		m = step3(pubKey, s, m)
	}
	fmt.Println()
}

func oracle(privKey rsa.PrivKey, ciphertext []byte, keySize int) bool {
	oracleCalled += 1
	plaintext := privKey.Decrypt(ciphertext)
	// leading 0x00 needs to be inferred
	leadingZero := len(plaintext) == (keySize - 1)
	return leadingZero && plaintext[0] == 0x02
}

func ceil(a *big.Int, b *big.Int) *big.Int {
	r := &big.Int{}
	m := &big.Int{}
	r.DivMod(a, b, m)
	if m.BitLen() == 0 {
		return r
	}
	r.Add(r, bigutils.One)
	return r
}

// Find the smallest s, such that c * s^e mod n is conformant
func step2a(pubKey rsa.PubKey, privKey rsa.PrivKey, keySizeBytes int, ciphertext, lowerBound *big.Int) *big.Int {
	s := &big.Int{}
	s.Set(lowerBound)
	for {
		nextCiphertext := &big.Int{}
		nextCiphertext.Exp(s, pubKey.E, pubKey.N)
		nextCiphertext.Mul(nextCiphertext, ciphertext)
		nextCiphertext.Mod(nextCiphertext, pubKey.N)
		if oracle(privKey, nextCiphertext.Bytes(), keySizeBytes) {
			return s
		}
		s.Add(s, bigutils.One)
	}
}

func step2c(pubKey rsa.PubKey, privKey rsa.PrivKey, keySizeBytes int, ciphertext *big.Int, interval Interval, s *big.Int) *big.Int {
	ri := &big.Int{}
	ri.Mul(interval.high, s)
	ri.Sub(ri, twoB)
	ri.Mul(ri, bigutils.Two)
	ri = ceil(ri, pubKey.N)

	nextS := &big.Int{}
	rin := &big.Int{}
	for {
		rin.Mul(ri, pubKey.N)

		lower := &big.Int{}
		lower.Add(twoB, rin)
		lower = ceil(lower, interval.high)

		higher := &big.Int{}
		higher.Add(threeBMinusOne, bigutils.One)
		higher.Add(higher, rin)
		higher = ceil(higher, interval.low)

		nextS.Set(lower)
		for nextS.Cmp(higher) == -1 {
			nextCiphertext := &big.Int{}
			nextCiphertext.Exp(nextS, pubKey.E, pubKey.N)
			nextCiphertext.Mul(nextCiphertext, ciphertext)
			nextCiphertext.Mod(nextCiphertext, pubKey.N)
			if oracle(privKey, nextCiphertext.Bytes(), keySizeBytes) {
				return nextS
			}
			nextS.Add(nextS, bigutils.One)
		}
		ri.Add(ri, bigutils.One)
	}
}

func step3(pubKey rsa.PubKey, newS *big.Int, intervals []Interval) []Interval {
	newM := []Interval{}
	for i := 0; i < len(intervals); i += 1 {
		interval := intervals[i]
		rLower := &big.Int{}
		rLower.Mul(interval.low, newS)
		rLower.Sub(rLower, threeBMinusOne)
		rLower = ceil(rLower, pubKey.N)

		rHigher := &big.Int{}
		rHigher.Mul(interval.high, newS)
		rHigher.Sub(rHigher, twoB)
		rHigher.Div(rHigher, pubKey.N)

		r := &big.Int{}
		r.Set(rLower)
		for r.Cmp(rHigher) != 1 {
			rn := &big.Int{}
			rn.Mul(r, pubKey.N)

			aa := &big.Int{}
			aa.Add(twoB, rn)
			aa = ceil(aa, newS)
			lower := bigutils.Max(interval.low, aa)

			bb := &big.Int{}
			bb.Add(threeBMinusOne, rn)
			bb.Div(bb, newS)
			higher := bigutils.Min(interval.high, bb)

			if lower.Cmp(higher) != 1 {
				newM = intervalAppend(newM, lower, higher)
			}
			r.Add(r, bigutils.One)
		}
	}
	return newM
}

// TODO: it's probably more efficient to use a tree, but I don't we'll have
// too many elements in the intervals slice.
//
// There's a bunch of cases we need to handle:
// case 1, no overlap: 1111
//
//	^^^
//
// case 2, no overlap:       11111
//
//	^^^^
//
// case 3, drop the new: 1111111
//
//	^^^
//
// case 4, drop the old:    1111
//
//	^^^^^^^^^
//
// case 5, left:      11111
//
//	^^^^^^^^
//
// case 6, right:    11111
//
//	^^^^^^
//
// keep in mind that each case can result in combining two or more intervals
// e.g. 1111  2222
//
//	    ^^^^^^
//
//	  1111  2222
//	^^^^^^^^^^^
func intervalAppend(intervals []Interval, newLow, newHigh *big.Int) []Interval {
	// check if we intersect any existing interval
	for i := 0; i < len(intervals); i++ {
		// It is easier to detect when there's no overlap, either:
		// - newLow is greater than high
		// - newHigh is smaller than low
		interval := intervals[i]
		if interval.low.Cmp(newHigh) == 1 || interval.high.Cmp(newLow) == -1 {
			continue
		}

		// We have an overlap. Remove the element we overlap with and call
		// intervalAppend recursively.
		newNewLow := bigutils.Min(interval.low, newLow)
		newNewHigh := bigutils.Max(interval.high, newHigh)

		// TODO: case 3 could be optimzed

		// TODO: we could just pop the last element instead of shifting everything
		newIntervals := append(intervals[:i], intervals[i+1:]...)
		return intervalAppend(newIntervals, newNewLow, newNewHigh)
	}

	s := &big.Int{}
	s.Sub(newHigh, newLow)
	s.Add(s, bigutils.One)
	return append(intervals, Interval{low: newLow, high: newHigh, size: s})
}

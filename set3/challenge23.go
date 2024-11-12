package set3

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge23(rng *rng.Rng) {
	utils.PrintTitle(3, 23)

	seed := uint32(rng.Uint64())

	rng1 := NewMT(seed)
	rng2 := clone(rng1)

	ok := 0
	n := 10000
	for i := 0; i < n; i++ {
		if rng1.next() == rng2.next() {
			ok++
		}
	}
	fmt.Printf("%d / %d\n", ok, n)
	fmt.Println()
}

func clone(rng *MT) *MT {
	r := NewMT(0)
	r.index = 0
	for i := 0; i < N; i++ {
		y5 := rng.next()
		y4 := undo_xor_shift_right(y5, L)
		y3 := undo_xor_shift_left_and(y4, T, C)
		y2 := undo_xor_shift_left_and(y3, S, B)
		y1 := undo_xor_shift_right(y2, U)
		r.state[r.index] = y1
		r.index++
	}

	return r
}

func undo_xor_shift_right(v uint32, shift int) uint32 {
	// the operation we need to undo:
	//                     33222222 22221111 111111
	//                     10987654 32109876 54321098 76543210
	//                 r = abcdefgh ijklmnop qrstuvwx yzABCDEF
	//        r >> shift = 00000000 000abcde fghijklm nopqrstu
	//                 v = abcdefgh ijk..... ........ ........

	// convert v to an array
	va := [32]bool{}
	for i := 31; i >= 0; i-- {
		va[i] = (v>>i)&1 == 1
	}

	// fill high bits
	ra := [32]bool{}
	overlap := 32 - shift
	for i := 31; i >= overlap; i-- {
		ra[i] = va[i]
	}

	// fill remaining bits using xor
	for i := overlap - 1; i >= 0; i-- {
		ra[i] = boolxor(va[i], ra[i+shift])
	}

	// convert back to uint
	r := uint32(0)
	for i := 31; i >= 0; i-- {
		if ra[i] {
			r = (r << 1) | 1
		} else {
			r = (r << 1)
		}
	}
	return r
}

func undo_xor_shift_left_and(v uint32, shift, and int) uint32 {
	// the operation we need to undo:
	//                      33222222 22221111 111111
	//                      10987654 32109876 54321098 76543210
	//                  r = abcdefgh ijklmnop qrstuvwx yzABCDEF
	//         r << shift = hijklmno pqrstuvw xyzABCDE F0000000
	//                and = 10011101 00101100 01010110 10000000
	// (r << shift) & and = h00klm0o 00r0tu00 0y0A0CD0 F0000000
	//                  v = .bc...g. ij.l..op q.s.u..x .zABCDEF
	//                      h  klm o   r tu    y A CD  F
	//                      a  def h   k mn    r t vw  y
	// convert v to an array
	va := [32]bool{}
	for i := 31; i >= 0; i-- {
		va[i] = (v>>i)&1 == 1
	}

	anda := [32]bool{}
	for i := 31; i >= 0; i-- {
		anda[i] = (and>>i)&1 == 1
	}

	// fill low bits
	ra := [32]bool{}
	for i := 0; i < shift; i++ {
		ra[i] = va[i]
	}

	// fill remaining bits using xor depending on and's value
	for i := shift; i < 32; i++ {
		if anda[i] {
			ra[i] = boolxor(va[i], ra[i-shift])
		} else {
			ra[i] = va[i]
		}
	}

	// convert back to uint
	r := uint32(0)
	for i := 31; i >= 0; i-- {
		if ra[i] {
			r = (r << 1) | 1
		} else {
			r = (r << 1)
		}
	}
	return r
}

func boolxor(v1, v2 bool) bool {
	t1 := 0
	if v1 {
		t1 = 1
	}
	t2 := 0
	if v2 {
		t2 = 1
	}
	return (t1 ^ t2) == 1
}

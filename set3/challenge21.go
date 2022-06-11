package set3

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// Mersenne twister: a 623-dimensionally equidistributed uniform pseudo-random number
// generator:
// http://www.math.sci.hiroshima-u.ac.jp/m-mat/MT/ARTICLES/mt.pdf
// W = 32 is implied
const N = 624
const M = 397
const R = 31
const A = 0x9908B0DF
const U = 11
const D = 0xFFFFFFFF
const S = 7
const B = 0x9D2C5680
const T = 15
const C = 0xEFC60000
const L = 18
const F = 1812433253
const LOWER_MASK = (1 << R) - 1
const UPPER_MASK = 1 << R

type MT struct {
	state [N]uint32
	index int
}

func NewMT(seed uint32) *MT {
	mt := &MT{
		state: [N]uint32{},
		index: N,
	}
	mt.state[0] = seed
	for i := 1; i < N; i++ {
		t := mt.state[i-1]
		// note: this initialization method is compatible with PHP. The original implementation
		// is different.
		mt.state[i] = F*(t^(t>>30)) + uint32(i)
	}
	return mt
}

func (mt *MT) next() uint32 {
	if mt.index == N {
		mt.twist()
	}
	y1 := mt.state[mt.index]
	y2 := y1 ^ ((y1 >> U) & D)
	y3 := y2 ^ ((y2 << S) & B)
	y4 := y3 ^ ((y3 << T) & C)
	y5 := y4 ^ (y4 >> L)

	mt.index++
	return y5
}

func (mt *MT) twist() {
	for i := 0; i < N; i++ {
		offset := (i + 1) % N
		x := (mt.state[i] & UPPER_MASK) + (mt.state[offset] & LOWER_MASK)
		xA := x >> 1
		if (x % 2) != 0 {
			xA = xA ^ A
		}
		offset = (i + M) % N
		mt.state[i] = mt.state[offset] ^ xA
	}
	mt.index = 0
}

func Challenge21() {
	utils.PrintTitle(3, 21)

	rng := NewMT(1234)

	// Verify we get the expected output
	file, err := ioutil.ReadFile("set3/21.txt")
	utils.PanicOnErr(err)
	values := strings.Split(string(file), "\n")
	ok := 0
	for _, value := range values {
		// set3/21.txt was generated using PHP, which returns 31 bits of entropy
		// https://github.com/alokmenghrajani/random_stuff/blob/master/cryptopals/src/set3/21_gen_test_vector.php
		t, err := strconv.Atoi(value)
		utils.PanicOnErr(err)
		expected := uint32(t)
		x := rng.next()
		if (x >> 1) == expected {
			ok++
		}
	}
	fmt.Printf("%d / %d\n", ok, len(values))

	fmt.Println()
}

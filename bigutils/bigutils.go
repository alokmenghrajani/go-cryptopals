package bigutils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// Be careful not to mutate these!
var Zero = big.NewInt(0)
var One = big.NewInt(1)
var Two = big.NewInt(2)
var Three = big.NewInt(3)

// Root from https://rosettacode.org/wiki/Integer_roots#big.Int
func Root(N int, xx *big.Int) *big.Int {
	x := &big.Int{}
	Δr := &big.Int{}
	nn := big.NewInt(int64(N))
	r := big.NewInt(1)
	for {
		x.Set(xx)
		for i := 1; i < N; i++ {
			x.Quo(x, r)
		}

		// big.Quo performs Go-like truncated division and would allow direct
		// translation of the int-based solution, but package big also provides
		// Div which performs Euclidean rather than truncated division.
		// This gives the desired result for negative x so the int-based
		// correction is no longer needed and the code here can more directly
		// follow the Wikipedia article.
		Δr.Div(x.Sub(x, r), nn)
		if IsZero(Δr) {
			return r
		}
		r.Add(r, Δr)
	}
}

// Returns a random number in the range [1, n-1]
func Randn(n *big.Int) *big.Int {
	for {
		buf := make([]byte, n.BitLen()/8)
		_, err := rand.Read(buf)
		utils.PanicOnErr(err)
		x := &big.Int{}
		x.SetBytes(buf)
		if x.Cmp(n) != -1 {
			continue
		}
		if IsZero(x) {
			continue
		}
		return x
	}
}

func Max(a *big.Int, b *big.Int) *big.Int {
	t := a.Cmp(b)
	if t == -1 {
		return b
	}
	return a
}

func Min(a *big.Int, b *big.Int) *big.Int {
	t := a.Cmp(b)
	if t == -1 {
		return a
	}
	return b
}

func IsZero(a *big.Int) bool {
	return a.BitLen() == 0
}

// Crt (Chinese Remainder Theorem) code from
// https://github.com/alokmenghrajani/adventofcode2020/blob/main/day13/day13.go#L61
func Crt(a, n []*big.Int) (*big.Int, error) {
	p := &big.Int{}
	p.Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	x := &big.Int{}
	q := &big.Int{}
	s := &big.Int{}
	z := &big.Int{}
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, s, n1, q)
		if z.Cmp(One) != 0 {
			return nil, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(x, s.Mul(a[i], s.Mul(s, q)))
		x.Mod(x, p)
	}
	return x, nil
}

func SetString(s string, base int) *big.Int {
	r := &big.Int{}
	_, ok := r.SetString(s, base)
	if !ok {
		panic("SetString failed")
	}
	return r
}

func FromBytes(data []byte) *big.Int {
	r := &big.Int{}
	r.SetBytes(data)
	return r
}

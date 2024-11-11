package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// Root from https://rosettacode.org/wiki/Integer_roots#big.Int
func Root(N int, xx *big.Int) *big.Int {
	var x, Δr big.Int
	nn := big.NewInt(int64(N))
	for r := big.NewInt(1); ; {
		x.Set(xx)
		for i := 1; i < N; i++ {
			x.Quo(&x, r)
		}
		// big.Quo performs Go-like truncated division and would allow direct
		// translation of the int-based solution, but package big also provides
		// Div which performs Euclidean rather than truncated division.
		// This gives the desired result for negative x so the int-based
		// correction is no longer needed and the code here can more directly
		// follow the Wikipedia article.
		Δr.Div(x.Sub(&x, r), nn)
		if len(Δr.Bits()) == 0 {
			return r
		}
		r.Add(r, &Δr)
	}
}

func Randn(n *big.Int) *big.Int {
	for {
		buf := make([]byte, n.BitLen()/8)
		_, err := rand.Read(buf)
		PanicOnErr(err)
		x := &big.Int{}
		x.SetBytes(buf)
		if x.Cmp(n) != -1 {
			continue
		}
		if x.Cmp(big.NewInt(0)) != 1 {
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
		if z.Cmp(big.NewInt(1)) != 0 {
			return nil, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(x, s.Mul(a[i], s.Mul(s, q)))
		x.Mod(x, p)
	}
	return x, nil
}

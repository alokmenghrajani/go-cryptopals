package set5

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/rsa"
)

func Challenge40() {
	utils.PrintTitle(5, 40)

	// create 3 keys
	pubKey1, _ := rsa.GenerateKeyPair()
	pubKey2, _ := rsa.GenerateKeyPair()
	pubKey3, _ := rsa.GenerateKeyPair()

	// encrypt a message 3 times
	msg := "attack at dawn"
	c1 := &big.Int{}
	c1.SetBytes([]byte(pubKey1.Encrypt([]byte(msg))))

	c2 := &big.Int{}
	c2.SetBytes([]byte(pubKey2.Encrypt([]byte(msg))))

	c3 := &big.Int{}
	c3.SetBytes([]byte(pubKey3.Encrypt([]byte(msg))))

	// Crack the ciphertexts using CRT
	solution, err := crt([]*big.Int{c1, c2, c3}, []*big.Int{pubKey1.N, pubKey2.N, pubKey3.N})
	utils.PanicOnErr(err)
	s := root(3, solution)

	fmt.Printf("plaintext: %s\n", msg)
	fmt.Printf("decrypted: %s\n", string(s.Bytes()))

	fmt.Println()
}

// Chinese Remainder Theorem code from
// https://github.com/alokmenghrajani/adventofcode2020/blob/main/day13/day13.go#L61
func crt(a, n []*big.Int) (*big.Int, error) {
	p := new(big.Int).Set(n[0])
	for _, n1 := range n[1:] {
		p.Mul(p, n1)
	}
	var x, q, s, z big.Int
	for i, n1 := range n {
		q.Div(p, n1)
		z.GCD(nil, &s, n1, &q)
		if z.Cmp(big.NewInt(1)) != 0 {
			return nil, fmt.Errorf("%d not coprime", n1)
		}
		x.Add(&x, s.Mul(a[i], s.Mul(&s, &q)))
	}
	return x.Mod(&x, p), nil
}

// root from https://rosettacode.org/wiki/Integer_roots#big.Int
func root(N int, xx *big.Int) *big.Int {
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

package set5

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/rsa"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge40() {
	utils.PrintTitle(5, 40)

	// create 3 keys
	pubKey1, _ := rsa.GenerateKeyPair(1024)
	pubKey2, _ := rsa.GenerateKeyPair(1024)
	pubKey3, _ := rsa.GenerateKeyPair(1024)

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
	s := utils.Root(3, solution)

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

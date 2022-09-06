package set5

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
	"github.com/alokmenghrajani/go-cryptopals/utils/rsa"
)

func Challenge40() {
	utils.PrintTitle(5, 40)

	// create 3 keys
	pubKey1, _ := rsa.GenerateKeyPair(1024)
	pubKey2, _ := rsa.GenerateKeyPair(1024)
	pubKey3, _ := rsa.GenerateKeyPair(1024)

	// encrypt a message 3 times
	msg := "attack at dawn"
	c1 := big.FromBytes([]byte(pubKey1.Encrypt([]byte(msg))))
	c2 := big.FromBytes([]byte(pubKey2.Encrypt([]byte(msg))))
	c3 := big.FromBytes([]byte(pubKey3.Encrypt([]byte(msg))))

	// Crack the ciphertexts using CRT
	solution, err := crt([]*big.Int{c1, c2, c3}, []*big.Int{pubKey1.N, pubKey2.N, pubKey3.N})
	utils.PanicOnErr(err)
	s := solution.Root(3)

	fmt.Printf("plaintext: %s\n", msg)
	fmt.Printf("decrypted: %s\n", string(s.Bytes()))

	fmt.Println()
}

// Chinese Remainder Theorem code from
// https://github.com/alokmenghrajani/adventofcode2020/blob/main/day13/day13.go#L61
func crt(a, n []*big.Int) (*big.Int, error) {
	p := n[0]
	for _, n1 := range n[1:] {
		p = p.Mul(n1)
	}
	x := big.Zero
	for i, n1 := range n {
		q, _ := p.Div(n1)
		_, s, z := n1.ExtendedGCD(q)
		if z.Cmp(big.One) != 0 {
			return nil, fmt.Errorf("%d not coprime", n1)
		}
		x = x.Add(a[i].Mul(s.Mul(q)))
	}
	return x.Mod(p), nil
}

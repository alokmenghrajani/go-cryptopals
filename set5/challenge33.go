package set5

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge33(rng *rng.Rng) {
	utils.PrintTitle(5, 33)

	dh(rng, big.NewInt(37), big.NewInt(5))

	p := bigutils.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	dh(rng, p, bigutils.Two)

	fmt.Println()
}

func dh(rng *rng.Rng, p, g *big.Int) {
	fmt.Printf("Diffie-Hellman with\np: %s\ng: %s\n\n", p.String(), g.String())
	a := rng.BigInt(p)

	A := &big.Int{}
	A.Exp(g, a, p)
	fmt.Printf("private key a: %s\n", a.String())
	fmt.Printf("public key A: %s\n\n", A.String())

	b := rng.BigInt(p)

	B := &big.Int{}
	B.Exp(g, b, p)
	fmt.Printf("private key b: %s\n", b.String())
	fmt.Printf("public key B: %s\n\n", B.String())

	s1 := &big.Int{}
	s1.Exp(B, a, p)
	fmt.Printf("s1: %s\n", s1.String())

	s2 := &big.Int{}
	s2.Exp(A, b, p)
	fmt.Printf("s2: %s\n", s2.String())

	if s1.Cmp(s2) != 0 {
		panic("oops")
	}
	fmt.Printf("ok\n\n")
}

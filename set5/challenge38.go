package set5

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/hmacSha256"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge38() {
	utils.PrintTitle(5, 38)

	performMitm := true

	rand.Seed(time.Now().Unix())
	N := &big.Int{}
	_, ok := N.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	if !ok {
		panic("SetString failed")
	}

	g := big.NewInt(2)
	k := big.NewInt(3)

	// part 1: save password
	I := "foo@bar.com"
	P := "sup3r s3cr3t"
	store := savePassword(g, N, I, P)

	// part 2: start authentication
	a := big.NewInt(int64(rand.Int()))
	a.Mod(a, N)
	var A big.Int
	A.Exp(g, a, N)
	salt, B, u := simplifiedAuthStep1(store, I, N, g, k)

	// MITM gets to modify salt, b, B, and u.
	// If we set B = g, the MITM gets to bruteforce the password offline because
	// S becomes A * g**(ux).
	if performMitm {
		B = g
	}

	// Client computes K
	sha := utils.NewSha256()
	sha.Update(salt)
	sha.Update([]byte(P))

	xH := sha.Digest()
	x := byteSliceToBigInt(xH)

	S := &big.Int{}
	t := &big.Int{}
	t.Mul(u, x)
	t.Add(a, t)
	S.Exp(B, t, N)

	sha = utils.NewSha256()
	sha.Update(S.Bytes())
	K := sha.Digest()

	// Client sends hmac
	proof := hmacSha256.Compute(K, salt)

	// MITM can crack the password
	if performMitm {
		dictionnary := []string{"ba53ba11", "sup3r s3cr3t", "pa5ta lov3r"}
		for _, p := range dictionnary {
			sha := utils.NewSha256()
			sha.Update(salt)
			sha.Update([]byte(p))
			xH2 := sha.Digest()
			x2 := byteSliceToBigInt(xH2)
			t2 := &big.Int{}
			t2.Mul(u, x2)
			t2.Exp(g, t2, N)
			t2.Mul(t2, &A)
			t2.Mod(t2, N)

			sha = utils.NewSha256()
			sha.Update(t2.Bytes())
			K2 := sha.Digest()
			proof2 := hmacSha256.Compute(K2, salt)
			fmt.Printf("%s: %v\n", p, bytes.Equal(proof, proof2))
		}
	} else {
		res := simplifiedAuthStep2(store, &A, N, proof)
		fmt.Printf("%v\n", res)
	}

	fmt.Println()
}

func simplifiedAuthStep1(store *passwordStore, I string, N, g, k *big.Int) ([]byte, *big.Int, *big.Int) {
	if store.I != I {
		panic("invalid identity")
	}

	store.b = big.NewInt(int64(rand.Int()))
	store.b.Mod(store.b, N)
	store.B = &big.Int{}
	store.B.Exp(g, store.b, N)

	store.u = big.NewInt(int64(rand.Int()))

	return store.salt, store.B, store.u
}

func simplifiedAuthStep2(store *passwordStore, A, N *big.Int, proof []byte) bool {
	var S big.Int
	S.Exp(store.v, store.u, N)
	S.Mul(&S, A)
	S.Exp(&S, store.b, N)

	sha := utils.NewSha256()
	sha.Update(S.Bytes())
	K := sha.Digest()

	expectedProof := hmacSha256.Compute(K, store.salt)
	return bytes.Equal(expectedProof, proof)
}

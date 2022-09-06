package set5

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
)

func Challenge38() {
	utils.PrintTitle(5, 38)

	performMitm := true

	rand.Seed(time.Now().Unix())
	N := big.FromBytes(utils.HexToByteSlice("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"))

	g := big.NewInt(2)
	k := big.NewInt(3)

	// part 1: save password
	I := "foo@bar.com"
	P := "sup3r s3cr3t"
	store := savePassword(g, N, I, P)

	// part 2: start authentication
	a := big.NewInt(rand.Int63())
	a = a.Mod(N)
	A := g.ExpMod(a, N)
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
	x := big.FromBytes(xH)

	t := u.Mul(x)
	t = t.Add(a)
	S := B.ExpMod(t, N)

	sha = utils.NewSha256()
	sha.Update(S.Bytes())
	K := sha.Digest()

	// Client sends hmac
	proof := utils.HmacSha256(K, salt)

	// MITM can crack the password
	if performMitm {
		dictionnary := []string{"ba53ba11", "sup3r s3cr3t", "pa5ta lov3r"}
		for _, p := range dictionnary {
			sha := utils.NewSha256()
			sha.Update(salt)
			sha.Update([]byte(p))
			xH2 := sha.Digest()
			x2 := big.FromBytes(xH2)
			t2 := u.Mul(x2)
			t2 = g.ExpMod(t2, N)
			t2 = t2.Mul(A)
			t2 = t2.Mod(N)

			sha = utils.NewSha256()
			sha.Update(t2.Bytes())
			K2 := sha.Digest()
			proof2 := utils.HmacSha256(K2, salt)
			fmt.Printf("%s: %v\n", p, bytes.Equal(proof, proof2))
		}
	} else {
		res := simplifiedAuthStep2(store, A, N, proof)
		fmt.Printf("%v\n", res)
	}

	fmt.Println()
}

func simplifiedAuthStep1(store *passwordStore, I string, N, g, k *big.Int) ([]byte, *big.Int, *big.Int) {
	if store.I != I {
		panic("invalid identity")
	}

	store.b = big.NewInt(rand.Int63())
	store.b = store.b.Mod(N)
	store.B = g.ExpMod(store.b, N)

	store.u = big.NewInt(rand.Int63())

	return store.salt, store.B, store.u
}

func simplifiedAuthStep2(store *passwordStore, A, N *big.Int, proof []byte) bool {
	S := store.v.ExpMod(store.u, N)
	S = S.Mul(A)
	S = S.ExpMod(store.b, N)

	sha := utils.NewSha256()
	sha.Update(S.Bytes())
	K := sha.Digest()

	expectedProof := utils.HmacSha256(K, store.salt)
	return bytes.Equal(expectedProof, proof)
}

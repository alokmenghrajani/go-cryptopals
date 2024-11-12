package set5

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/hmacSha256"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha256"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// http://srp.stanford.edu/doc.html
// https://en.wikipedia.org/wiki/Secure_Remote_Password_protocol

type passwordStore struct {
	I    string
	salt []byte
	v    *big.Int
	b    *big.Int
	B    *big.Int
	u    *big.Int
}

func Challenge36(rng *rng.Rng) {
	utils.PrintTitle(5, 36)

	N := bigutils.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := bigutils.Two
	k := bigutils.Three

	// part 1: save password
	I := "foo@bar.com"
	P := "sup3r s3cr3t"
	store := savePassword(rng, g, N, I, P)

	// part 2: start authentication
	a := rng.BigInt(N)
	A := &big.Int{}
	A.Exp(g, a, N)
	salt, B := authStep1(rng, store, I, N, g, k)

	// Client computes K
	sha := sha256.New()
	sha.Update(A.Bytes())
	sha.Update(B.Bytes())

	uH := sha.Digest()
	u := bigutils.FromBytes(uH)

	sha = sha256.New()
	sha.Update(salt)
	sha.Update([]byte(P))

	xH := sha.Digest()
	x := bigutils.FromBytes(xH)

	S := &big.Int{}
	S.Exp(g, x, N)
	S.Mul(S, k)
	S.Sub(B, S)
	S.Mod(S, N)

	t := &big.Int{}
	t.Mul(u, x)
	t.Add(a, t)
	S.Exp(S, t, N)

	sha = sha256.New()
	sha.Update(S.Bytes())
	K := sha.Digest()

	// Client sends hmac
	proof := hmacSha256.Compute(K, salt)
	res := authStep2(store, A, N, proof)
	fmt.Printf("%v\n", res)

	fmt.Println()
}

// The whole point of SRP is that the server doesn't get a copy of the password ¯\_(ツ)_/¯
// This is probably a mistake in the challenge write up.
func savePassword(rng *rng.Rng, g, N *big.Int, I, P string) *passwordStore {
	r := passwordStore{
		I: I,
		v: &big.Int{},
	}

	r.salt = []byte(fmt.Sprintf("%d", rng.Uint64()))
	sha := sha256.New()
	sha.Update(r.salt)
	sha.Update([]byte(P))

	xH := sha.Digest()
	x := bigutils.FromBytes(xH)
	r.v.Exp(g, x, N)

	return &r
}

func authStep1(rng *rng.Rng, store *passwordStore, I string, N, g, k *big.Int) ([]byte, *big.Int) {
	if store.I != I {
		panic("invalid identity")
	}

	store.b = rng.BigInt(N)
	store.B = &big.Int{}
	store.B.Exp(g, store.b, N)
	t := &big.Int{}
	t.Mul(k, store.v)
	store.B.Add(t, store.B)

	// This isn't super clear in the challenge description, but a modulo operation is needed
	// here. More info here: https://www.computest.nl/nl/knowledge-platform/blog/exploiting-two-buggy-srp-implementations/
	store.B.Mod(store.B, N)

	return store.salt, store.B
}

func authStep2(store *passwordStore, A, N *big.Int, proof []byte) bool {
	sha := sha256.New()
	sha.Update(A.Bytes())
	sha.Update(store.B.Bytes())

	uH := sha.Digest()
	u := bigutils.FromBytes(uH)

	S := &big.Int{}
	S.Exp(store.v, u, N)
	S.Mul(S, A)
	S.Exp(S, store.b, N)

	sha = sha256.New()
	sha.Update(S.Bytes())
	K := sha.Digest()

	expectedProof := hmacSha256.Compute(K, store.salt)
	return bytes.Equal(expectedProof, proof)
}

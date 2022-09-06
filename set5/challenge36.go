package set5

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
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

func Challenge36() {
	utils.PrintTitle(5, 36)

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
	salt, B := authStep1(store, I, N, g, k)

	// Client computes K
	sha := utils.NewSha256()
	sha.Update(A.Bytes())
	sha.Update(B.Bytes())

	uH := sha.Digest()
	u := big.FromBytes(uH)

	sha = utils.NewSha256()
	sha.Update(salt)
	sha.Update([]byte(P))

	xH := sha.Digest()
	x := big.FromBytes(xH)

	S := g.ExpMod(x, N)
	S = S.Mul(k)
	S2 := B.Sub(S)
	if S2 == nil {
		// TODO: this isn't correct but works for now
		S2 = B.Add(N).Sub(S)
	}
	S = S2.Mod(N)

	t := u.Mul(x)
	t = t.Add(a)
	S = S.ExpMod(t, N)

	sha = utils.NewSha256()
	sha.Update(S.Bytes())
	K := sha.Digest()

	// Client sends hmac
	proof := utils.HmacSha256(K, salt)
	res := authStep2(store, A, N, proof)
	fmt.Printf("%v\n", res)

	fmt.Println()
}

// The whole point of SRP is that the server doesn't get a copy of the password ¯\_(ツ)_/¯
// This is probably a mistake in the challenge write up.
func savePassword(g, N *big.Int, I, P string) *passwordStore {
	r := passwordStore{
		I: I,
		v: &big.Int{},
	}

	r.salt = []byte(fmt.Sprintf("%d", rand.Int()))
	sha := utils.NewSha256()
	sha.Update(r.salt)
	sha.Update([]byte(P))

	xH := sha.Digest()
	x := big.FromBytes(xH)
	r.v = g.ExpMod(x, N)

	return &r
}

func authStep1(store *passwordStore, I string, N, g, k *big.Int) ([]byte, *big.Int) {
	if store.I != I {
		panic("invalid identity")
	}

	store.b = big.NewInt(rand.Int63())
	store.b = store.b.Mod(N)
	store.B = &big.Int{}
	store.B = g.ExpMod(store.b, N)
	t := k.Mul(store.v)
	store.B = t.Add(store.B)

	// This isn't super clear in the challenge description, but a modulo operation is needed
	// here. More info here: https://www.computest.nl/nl/knowledge-platform/blog/exploiting-two-buggy-srp-implementations/
	store.B = store.B.Mod(N)

	return store.salt, store.B
}

func authStep2(store *passwordStore, A, N *big.Int, proof []byte) bool {
	sha := utils.NewSha256()
	sha.Update(A.Bytes())
	sha.Update(store.B.Bytes())

	uH := sha.Digest()
	u := big.FromBytes(uH)

	S := store.v.ExpMod(u, N)
	S = S.Mul(A)
	S = S.ExpMod(store.b, N)

	sha = utils.NewSha256()
	sha.Update(S.Bytes())
	K := sha.Digest()

	expectedProof := utils.HmacSha256(K, store.salt)
	return bytes.Equal(expectedProof, proof)
}

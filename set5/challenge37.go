package set5

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/hmacSha256"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha256"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge37(rng *rng.Rng) {
	utils.PrintTitle(5, 37)

	N := bigutils.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := bigutils.Two
	k := bigutils.Three

	// part 1: save password
	I := "foo@bar.com"
	P := "sup3r s3cr3t"
	store := savePassword(rng, g, N, I, P)

	// part 2: start authentication to grab salt
	salt, _ := authStep1(rng, store, I, N, g, k)

	// We know the value for S, skip computing it
	S := bigutils.Zero

	// Derive K
	sha := sha256.New()
	sha.Update(S.Bytes())
	K := sha.Digest()

	// Client sends hmac
	proof := hmacSha256.Compute(K, salt)

	for i := 0; i < 3; i++ {
		A := &big.Int{}
		A.Mul(N, big.NewInt(int64(i)))
		res := authStep2(store, A, N, proof)
		fmt.Printf("%d*N: %v\n", i, res)
	}

	fmt.Println()
}

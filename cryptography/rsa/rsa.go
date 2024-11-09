package rsa

import (
	"crypto/rand"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type PubKey struct {
	E *big.Int `json:"E"`
	N *big.Int `json:"N"`
}

type PrivKey struct {
	D *big.Int `json:"D"`
	N *big.Int `json:"N"`
}

func GenerateKeyPair(keySizeBits int) (PubKey, PrivKey) {
	for {
		p := randomPrime(keySizeBits / 2)
		q := randomPrime(keySizeBits / 2)

		n := &big.Int{}
		n.Mul(p, q)

		if n.BitLen() != keySizeBits {
			panic("n does not have expected bitLen")
		}

		p2 := &big.Int{}
		p2.Sub(p, big.NewInt(1))
		q2 := &big.Int{}
		q2.Sub(q, big.NewInt(1))
		et := &big.Int{}
		et.Mul(p2, q2)

		e := big.NewInt(3)

		extraCheck := &big.Int{}
		extraCheck.GCD(nil, nil, e, et)
		if extraCheck.Cmp(big.NewInt(1)) == 0 {
			d := &big.Int{}
			d.ModInverse(e, et)

			return PubKey{E: e, N: n}, PrivKey{D: d, N: n}
		}
	}
}

func (key PubKey) Encrypt(plaintext []byte) []byte {
	m := &big.Int{}
	m.SetBytes(plaintext)

	if m.Cmp(key.N) != -1 {
		panic("message too large for key")
	}

	c := &big.Int{}
	c.Exp(m, key.E, key.N)

	return c.Bytes()
}

func (key PrivKey) Decrypt(ciphertext []byte) []byte {
	c := &big.Int{}
	c.SetBytes(ciphertext)

	m := &big.Int{}
	m.Exp(c, key.D, key.N)

	return m.Bytes()
}

func (key PrivKey) Sign(message []byte) []byte {

	m := &big.Int{}
	m.SetBytes(message)

	if m.Cmp(key.N) != -1 {
		panic("message too large for key")
	}

	c := &big.Int{}
	c.Exp(m, key.D, key.N)

	return c.Bytes()
}

func (key PubKey) Verify(signature []byte) []byte {
	c := &big.Int{}
	c.SetBytes(signature)

	m := &big.Int{}
	m.Exp(c, key.E, key.N)

	// Since we are dealing with BigInt, we don't have any leading 0x00.

	return m.Bytes()
}

func randomPrime(keySizeBits int) *big.Int {
	for {
		buf := make([]byte, keySizeBits/8)
		_, err := rand.Read(buf)
		utils.PanicOnErr(err)

		// Set the two most significant bits to 1 to guarantee that the resulting product will
		// have the right number length.
		// Looking at how common crypto libraries generate RSA keys is quite terrifying -- I wouldn't use RSA
		// again for anything :)
		//
		// Here is how Golang handles key generation. It's quite more complicated since they handle multi-prime (when
		// more than two primes are used, see https://datatracker.ietf.org/doc/html/rfc3447#section-3). The two higher bits get set.
		// https://cs.opensource.google/go/go/+/refs/tags/go1.19:src/crypto/rsa/rsa.go;l=321;drc=de95dca32fb196d5f09bf5db4a6ba592907559c3
		//
		// Java Bouncycastle's implementation is here. A bit different from my approach:
		// https://github.com/bcgit/bc-java/blob/bc3b92f1f0e78b82e2584c5fb4b226a13e7f8b3b/core/src/main/java/org/bouncycastle/crypto/generators/RSAKeyPairGenerator.java#L72
		//
		// BoringSSL's implementation is quite readable. I like this comment: "The key generation process is complex and thus error-prone. It could
		// be disastrous to generate and then use a bad key so double-check that the key makes sense."
		// https://github.com/google/boringssl/blob/b7d6320be91bdf132349e8384bd779ffcff3f030/crypto/fipsmodule/rsa/rsa_impl.c#L1258
		buf[0] = buf[0] | 0xc0

		n := &big.Int{}
		n.SetBytes(buf)
		if n.ProbablyPrime(20) {
			return n
		}
	}
}

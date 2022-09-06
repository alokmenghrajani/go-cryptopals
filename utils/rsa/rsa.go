package rsa

import (
	"crypto/rand"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
)

type PubKey struct {
	E *big.Int
	N *big.Int
}

type PrivKey struct {
	D *big.Int
	N *big.Int
}

func GenerateKeyPair(keySizeBits int) (PubKey, PrivKey) {
	for {
		p := randomPrime(keySizeBits / 2)
		q := randomPrime(keySizeBits / 2)

		n := p.Mul(q)

		if n.Msb() != keySizeBits {
			panic("n does not have expected bitLen")
		}

		p2 := p.Sub(big.NewInt(1))
		q2 := q.Sub(big.NewInt(1))
		et := p2.Mul(q2)

		e := big.NewInt(3)

		_, _, extraCheck := e.ExtendedGCD(et)
		if extraCheck.Cmp(big.One) == 0 {
			d := e.ModInverse(et)

			return PubKey{E: e, N: n}, PrivKey{D: d, N: n}
		}
	}
}

func (key PubKey) Encrypt(plaintext []byte) []byte {
	m := big.FromBytes(plaintext)
	if m.Cmp(key.N) != -1 {
		panic("message too large for key")
	}

	c := m.ExpMod(key.E, key.N)
	return c.Bytes()
}

func (key PrivKey) Decrypt(ciphertext []byte) []byte {
	c := big.FromBytes(ciphertext)
	m := c.ExpMod(key.D, key.N)
	return m.Bytes()
}

func (key PrivKey) Sign(message []byte) []byte {
	m := big.FromBytes(message)
	if m.Cmp(key.N) != -1 {
		panic("message too large for key")
	}

	c := m.ExpMod(key.D, key.N)
	return c.Bytes()
}

func (key PubKey) Verify(signature []byte) []byte {
	c := big.FromBytes(signature)
	m := c.ExpMod(key.E, key.N)

	// Keep in mind that since we are dealing with big.Int, there won't be any leading 0x00.

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

		n := big.FromBytes(buf)
		if n.ProbablyPrime() {
			return n
		}
	}
}

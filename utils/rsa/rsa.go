package rsa

import (
	"crypto/rand"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type PubKey struct {
	E *big.Int
	N *big.Int
}

type PrivKey struct {
	D *big.Int
	N *big.Int
}

func GenerateKeyPair() (PubKey, PrivKey) {
	p := randomPrime()
	q := randomPrime()

	n := &big.Int{}
	n.Mul(p, q)

	p2 := &big.Int{}
	p2.Sub(p, big.NewInt(1))
	q2 := &big.Int{}
	q2.Sub(q, big.NewInt(1))
	et := &big.Int{}
	et.Mul(p2, q2)

	e := big.NewInt(3)

	d := &big.Int{}
	d.ModInverse(e, et)

	return PubKey{E: e, N: n}, PrivKey{D: d, N: n}
}

func (key PubKey) Encrypt(plaintext []byte) []byte {
	m := &big.Int{}
	m.SetBytes(plaintext)

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

func randomPrime() *big.Int {
	for {
		buf := make([]byte, 16)
		_, err := rand.Read(buf)
		utils.PanicOnErr(err)

		n := &big.Int{}
		n.SetBytes(buf)
		if n.ProbablyPrime(20) {
			return n
		}
	}
}

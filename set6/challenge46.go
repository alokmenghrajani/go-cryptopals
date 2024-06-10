package set6

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/rsa"
	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge46() {
	utils.PrintTitle(6, 46)

	pubKey, privKey := rsa.GenerateKeyPair(1024)
	plaintext := base64.ToByteSlice("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
	ciphertext := pubKey.Encrypt(plaintext)

	// A naive implementation of the binary search will accumulate rounding errors and the
	// last byte will end up being incorrect. It is therefore more accurate to keep track
	// of the bounds by tracking the numerator/denominator.
	lowerBound := big.NewInt(0)
	upperBound := &big.Int{}
	upperBound.Set(pubKey.N)
	denominator := big.NewInt(1)

	c := &big.Int{}
	c.SetBytes(ciphertext)

	facTwo := &big.Int{}
	facTwo.Exp(big.NewInt(2), pubKey.E, pubKey.N)
	delta := &big.Int{}
	result := &big.Int{}

	previousLen := -1

	for {
		c.Mul(c, facTwo)
		delta.Sub(upperBound, lowerBound)
		if delta.Cmp(denominator) == -1 {
			break
		}
		lowerBound.Mul(lowerBound, big.NewInt(2))
		upperBound.Mul(upperBound, big.NewInt(2))
		denominator.Mul(denominator, big.NewInt(2))
		if parityOracle(privKey, c.Bytes()) {
			lowerBound.Add(lowerBound, delta)
			result.Div(lowerBound, denominator)
		} else {
			upperBound.Sub(upperBound, delta)
			result.Div(upperBound, denominator)
		}
		buf := result.Bytes()
		if len(buf) == previousLen && buf[0] >= 'A' && buf[0] <= 'z' {
			fmt.Printf("%q\n", string(result.Bytes()))
		}
		previousLen = len(buf)
	}
	result.Div(upperBound, denominator)
	fmt.Printf("plaintext: %s\n", string(result.Bytes()))
	if !bytes.Equal(result.Bytes(), plaintext) {
		panic("failed to decrypt")
	}

	fmt.Println()
}

func parityOracle(privKey rsa.PrivKey, ciphertext []byte) bool {
	plaintext := privKey.Decrypt(ciphertext)
	return plaintext[len(plaintext)-1]&0x1 == 1
}

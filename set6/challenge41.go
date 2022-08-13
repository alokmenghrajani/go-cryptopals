package set6

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/rsa"
)

func Challenge41() {
	utils.PrintTitle(6, 41)

	// create public key
	pubKey, privKey := rsa.GenerateKeyPair(1024)

	// encrypt a message
	originalCiphertext := pubKey.Encrypt([]byte("s3cr3t sauc3"))

	// modify the message
	c := &big.Int{}
	c.SetBytes(originalCiphertext)

	s := big.NewInt(2)
	c2 := &big.Int{}
	c2.Exp(s, pubKey.E, pubKey.N)
	c2.Mul(c2, c)
	c2.Mod(c2, pubKey.N)

	// decrypt the ciphertext
	plaintext2 := decrypt(privKey, originalCiphertext, c2.Bytes())
	p2 := &big.Int{}
	p2.SetBytes(plaintext2)

	p := &big.Int{}
	p.SetBytes([]byte("s3cr3t sauc3"))
	p.Mul(p, s)
	p.Mod(p, pubKey.N)

	s.ModInverse(s, pubKey.N)
	p2.Mul(p2, s)
	p2.Mod(p2, pubKey.N)

	fmt.Printf("%s\n", string(p2.Bytes()))

	fmt.Println()
}

func decrypt(privKey rsa.PrivKey, originalCiphertext []byte, ciphertext []byte) []byte {
	if bytes.Equal(originalCiphertext, ciphertext) {
		panic("ciphertexts are the same")
	}
	return privKey.Decrypt(ciphertext)
}

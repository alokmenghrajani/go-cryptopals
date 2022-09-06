package set6

import (
	"bytes"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
	"github.com/alokmenghrajani/go-cryptopals/utils/rsa"
)

func Challenge41() {
	utils.PrintTitle(6, 41)

	// create public key
	pubKey, privKey := rsa.GenerateKeyPair(1024)

	// encrypt a message
	originalCiphertext := pubKey.Encrypt([]byte("s3cr3t sauc3"))

	// modify the message
	c := big.FromBytes(originalCiphertext)

	s := big.NewInt(2)
	c2 := s.ExpMod(pubKey.E, pubKey.N)
	c2 = c2.Mul(c)
	c2 = c2.Mod(pubKey.N)

	// decrypt the ciphertext
	plaintext2 := decrypt(privKey, originalCiphertext, c2.Bytes())
	p2 := big.FromBytes(plaintext2)

	p := big.FromBytes([]byte("s3cr3t sauc3"))
	p = p.Mul(s)
	p = p.Mod(pubKey.N)

	s = s.ModInverse(pubKey.N)
	p2 = p2.Mul(s)
	p2 = p2.Mod(pubKey.N)

	fmt.Printf("%s\n", string(p2.Bytes()))

	fmt.Println()
}

func decrypt(privKey rsa.PrivKey, originalCiphertext []byte, ciphertext []byte) []byte {
	if bytes.Equal(originalCiphertext, ciphertext) {
		panic("ciphertexts are the same")
	}
	return privKey.Decrypt(ciphertext)
}

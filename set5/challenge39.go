package set5

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/rsa"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge39() {
	utils.PrintTitle(5, 39)

	pubKey, privKey := rsa.GenerateKeyPair(1024)

	// encrypt a message
	msg := "attack at dawn"
	ciphertext := pubKey.Encrypt([]byte(msg))

	// decrypt c
	plaintext := privKey.Decrypt(ciphertext)

	fmt.Printf("plaintext: %s\n", msg)
	fmt.Printf("decrypted: %s\n", string(plaintext))

	fmt.Println()
}

package set5

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/rsa"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge40() {
	utils.PrintTitle(5, 40)

	// create 3 keys
	pubKey1, _ := rsa.GenerateKeyPair(1024)
	pubKey2, _ := rsa.GenerateKeyPair(1024)
	pubKey3, _ := rsa.GenerateKeyPair(1024)

	// encrypt a message 3 times
	msg := "attack at dawn"
	c1 := bigutils.FromBytes([]byte(pubKey1.Encrypt([]byte(msg))))

	c2 := bigutils.FromBytes([]byte(pubKey2.Encrypt([]byte(msg))))

	c3 := bigutils.FromBytes([]byte(pubKey3.Encrypt([]byte(msg))))

	// Crack the ciphertexts using CRT
	solution, err := bigutils.Crt([]*big.Int{c1, c2, c3}, []*big.Int{pubKey1.N, pubKey2.N, pubKey3.N})
	utils.PanicOnErr(err)
	s := bigutils.Root(3, solution)

	fmt.Printf("plaintext: %s\n", msg)
	fmt.Printf("decrypted: %s\n", string(s.Bytes()))

	fmt.Println()
}

package set2

import (
	"bytes"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type chall14 struct {
	chall12
	randPrefix   []byte
	prefixLength int
}

func Challenge14(rng *rng.Rng) {
	utils.PrintTitle(2, 14)

	c := chall14{}
	c.aesKey = rng.Bytes(aes.KeySize)

	// generate a random prefix of random length
	c.randPrefix = rng.Bytes(rng.Int(40) + 5)

	// step 1: find the prefixLength
	c.prefixLength = c.findPrefixLength(rng)
	if c.prefixLength != len(c.randPrefix) {
		// we aren't supposed to use randPrefix, so this is cheating. Helps figure out if we
		// messed anything up
		panic("findPrefixLength is broken")
	}

	// step 2: find the plaintextSize
	plaintextSize := c.findPlaintextSize()

	// step 3: crack
	plaintext := c.crack(plaintextSize)

	fmt.Println(string(plaintext))
	fmt.Println()
}

// We can add a few bytes to our prefix and then infer how many blocks of prefix we have by
// by looking for a duplicate block. Imagine our unknown prefix is "ab" and our target bytes are
// "abcdefghijklm", with a 4-byte block size. Two bytes is the minimum amount of bytes we need
// to have before zzzz gets repeated:
// "ab00 zzzz zzzz abcd efgh ijkl m333"
//
//	^^ ^^^^ ^^^^
func (c chall14) findPrefixLength(rng *rng.Rng) int {
	block := rng.Bytes(aes.BlockSize)

	for i := 0; i < 16; i++ {
		t := make([]byte, i)
		t = append(t, block...)
		t = append(t, block...)
		ciphertext := c.encryptHard(t)
		for j := 0; j < len(ciphertext)-16; j += 16 {
			if bytes.Equal(ciphertext[j:j+16], ciphertext[j+16:j+32]) {
				return j - i
			}
		}
	}
	panic("unreachable")
}

func (c chall14) encryptHard(data []byte) []byte {
	unknownString := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownBuf := base64.ToByteSlice(unknownString)
	buf := make([]byte, 0, len(c.randPrefix)+len(data)+len(unknownBuf))
	buf = append(buf, c.randPrefix...)
	buf = append(buf, data...)
	buf = append(buf, unknownBuf...)
	return aesEcbEncrypt(pkcs7.Pad(buf, aes.BlockSize), c.aesKey)
}

// Knowing the prefixLength puts us back in the simpler challenge 12 case
// func (c chall14) encrypt(data []byte) []byte {
// 	prefixRemaining := utils.Remaining(c.prefixLength, 16)
// 	firstBlock := (c.prefixLength + prefixRemaining) / 16

// 	t := make([]byte, prefixRemaining)
// 	t = append(t, data...)
// 	ciphertext := c.encryptHard(t)
// 	return ciphertext[firstBlock*16:]
// }

package set2

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type chall12 struct {
	aesKey []byte
}

func Challenge12() {
	utils.PrintTitle(2, 12)

	c := chall12{}
	c.genAesKey()

	plaintextSize := c.findPlaintextSize()
	plaintext := c.crack(plaintextSize)

	fmt.Println(string(plaintext))
	fmt.Println()
}

func (c *chall12) genAesKey() {
	c.aesKey = make([]byte, 16)
	_, err := rand.Read(c.aesKey)
	utils.PanicOnErr(err)
}

// step 1: keep prepending bytes until we get a new block. We'll then know how much plaintext
//
//	we have.
func (c chall12) findPlaintextSize() int {
	prefix := []byte{}
	r1 := c.encrypt(prefix)
	var r2 []byte
	for {
		prefix = append(prefix, 'x')
		r2 = c.encrypt(prefix)
		if len(r1) != len(r2) {
			break
		}
	}
	plaintextSize := len(r1) - len(prefix)
	if len(r2)-len(r1) != 16 {
		panic("expecting block size to be 16")
	}
	return plaintextSize
}

// step 2: use the known prefix to get one unknown byte at a time at the end of a block and then
// bruteforce that block.
func (c chall12) crack(plainttextSize int) []byte {
	// Imagine a 4-byte cipher and unknown string "abcdefghijkl".
	// "000" prefix lets us crack "a", the last byte of the first block:
	// 000a bcde fghi jkl
	//    ^
	//
	// Then reduce the prefix by one byte and crack "b":
	// 00ab cdef ghij kl
	//    ^
	//
	// Same process for "c" and "d":
	// 0abc defg hijk l
	//    ^
	//
	// abcd efgh ijkl
	//    ^
	//
	// We now know the first block. For the second block, we start over with
	// "000" but look at the last byte of the 2nd block:
	//
	// 000a bcde fghi jkl
	//         ^
	//
	// And so on...

	prefix := 15
	block := 0

	// To simplify the code, we prefix plaintext with 15 known bytes.
	plaintext := make([]byte, 15)
	for i := 0; i < plainttextSize; i++ {
		// TODO: this result can be cached to save a bunch of calls to the oracle.
		r1 := c.encrypt(plaintext[0:prefix])
		found := false
		for j := 0; j < 256; j++ {
			known := plaintext[len(plaintext)-15:]
			known = append(known, byte(j))
			r2 := c.encrypt(known)
			if bytes.Equal(r2[0:16], r1[block*16:block*16+16]) {
				found = true
				plaintext = append(plaintext, byte(j))
				break
			}
		}
		if !found {
			panic("fail")
		}
		prefix--
		if prefix < 0 {
			prefix = 15
			block++
		}
	}

	// Remove the 15 known bytes we added earlier
	return plaintext[15:]
}

func (c chall12) encrypt(data []byte) []byte {
	unknownString := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unknownBuf := base64.ToByteSlice(unknownString)
	buf := make([]byte, 0, len(data)+len(unknownBuf))
	buf = append(buf, data...)
	buf = append(buf, unknownBuf...)
	return aesEcbEncrypt(utils.Pad(buf, 16), c.aesKey)
}

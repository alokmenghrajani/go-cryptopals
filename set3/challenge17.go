package set3

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

func Challenge17() {
	utils.PrintTitle(3, 17)

	// generate random AES key
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	// iterate over each ciphertext
	for i := 0; i < 10; i++ {
		buf, iv := pick(i, aesKey)
		s := crack(buf, iv, aesKey)
		fmt.Println(string(s))
	}

	fmt.Println()
}

func pick(n int, aesKey []byte) ([]byte, []byte) {
	inputs := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	// generate random IV
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	utils.PanicOnErr(err)

	// base64 decode then encrypt data
	plaintext := base64.ToByteSlice(inputs[n])
	plaintext = utils.Pad(plaintext, 16)
	return aes.AesCbcEncrypt([]byte(plaintext), aesKey, iv), iv
}

// return true if the data is well padded
func paddingOracle(buf, iv, aesKey []byte) bool {
	t := aes.AesCbcDecrypt(buf, aesKey, iv)
	_, err := utils.Unpad(t, 16)
	return err == nil
}

// Crack the ciphertext using paddingOracle
func crack(buf, iv, aesKey []byte) []byte {
	plaintext := []byte{}
	previousBlock := iv

	// crack one block at a time
	for i := 0; i < len(buf); i += 16 {
		block := buf[i : i+16]

		// for each block, we'll mess with the previousBlock until we
		// get valid padding. We record the byte which leads to valid
		// padding xor the desired padding.
		validPadding := make([]byte, 16)
		alternate := -1
		for j := 15; j >= 0; j-- {
			desiredPadding := 16 - j
			copy := []byte{}
			copy = append(copy, previousBlock...)
			for k := j + 1; k < 16; k++ {
				copy[k] = validPadding[k] ^ byte(desiredPadding)
			}
			valid1, valid2, err := findValidPadding(j, block, copy, aesKey)
			if err != nil {
				// We have to handle the case where we land on [... 0x02 0x02] vs
				// [... 0x02 0x01]. Or [... 0x03 0x03 0x03] vs [... 0x03 0x03 0x01].
				// In all cases, this manifests itself when j=14 and the valid padding search
				// fails.
				if j != 14 {
					panic(fmt.Sprintf("findValidPadding failed on %d", j))
				}
				if alternate == -1 {
					panic("findValidPadding failed with no alternate")
				}
				validPadding[15] = byte(alternate) ^ byte(0x01)
				copy[15] = validPadding[15] ^ byte(desiredPadding)
				valid1, valid2, err = findValidPadding(j, block, copy, aesKey)
				utils.PanicOnErr(err)
			}
			validPadding[j] = byte(valid1) ^ byte(desiredPadding)

			// The alternate padding only happens for the first padding we look for. Save
			// it for later reuse
			if valid2 != -1 {
				if j != 15 {
					panic(fmt.Sprintf("alternate on %d", j))
				}
				alternate = valid2
			}
		}

		// validPadding xor previousBlock is the plaintext for this block
		plaintext = append(plaintext, utils.Xor(validPadding, previousBlock)...)
		previousBlock = block
	}

	plaintext, err := utils.Unpad(plaintext, 16)
	utils.PanicOnErr(err)
	return plaintext
}

func findValidPadding(offset int, block, iv, aesKey []byte) (int, int, error) {
	r1 := -1
	r2 := -1
	for i := 0; i < 256; i++ {
		iv[offset] = byte(i)
		if paddingOracle(block, iv, aesKey) {
			if r1 == -1 {
				r1 = i
			} else if r2 == -1 {
				r2 = i
			} else {
				panic("found more than two values")
			}
		}
	}
	if r1 == -1 {
		return -1, -1, errors.New("found no values")
	}
	return r1, r2, nil
}

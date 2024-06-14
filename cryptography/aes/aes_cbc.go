package aes

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// Decrypts an AES CBC encrypted buffer. Returns the padded buffer.
func AesCbcDecrypt(buf, key, iv []byte) []byte {
	plaintext := []byte{}

	if len(buf)%BlockSize != 0 {
		panic(fmt.Errorf("buf isn't a multiple of BlockSize: %d", len(buf)))
	}
	if len(iv) != BlockSize {
		panic(fmt.Errorf("iv length isn't BlockSize: %d", len(iv)))
	}

	aes := NewAes(key)

	prev := iv
	for i := 0; i < len(buf); i += BlockSize {
		ciphertext := buf[i : i+BlockSize]

		// Decrypt ciphertext
		output := make([]byte, BlockSize)
		aes.Decrypt(output, ciphertext)

		// XOR output with prev
		t := utils.Xor(output, prev)
		prev = ciphertext

		plaintext = append(plaintext, t...)
	}

	return plaintext
}

// Encrypts a padded buffer using AES CBC. Typically, pkcs7 will be used to
// pad the buffer.
func AesCbcEncrypt(buf, key, iv []byte) []byte {
	ciphertext := []byte{}

	if len(buf)%BlockSize != 0 {
		panic(fmt.Errorf("buf isn't a multiple of BlockSize: %d", len(buf)))
	}
	if len(iv) != BlockSize {
		panic(fmt.Errorf("iv length isn't BlockSize: %d", len(iv)))
	}

	aes := NewAes(key)

	prev := iv
	for i := 0; i < len(buf); i += BlockSize {
		plaintext := buf[i : i+BlockSize]

		// XOR plaintext with prev
		input := make([]byte, 0, BlockSize)
		for i := 0; i < BlockSize; i++ {
			input = append(input, plaintext[i]^prev[i])
		}

		// Encrypt input
		output := make([]byte, BlockSize)
		aes.Encrypt(output, input)
		prev = output

		ciphertext = append(ciphertext, output...)
	}

	return ciphertext
}

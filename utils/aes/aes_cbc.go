package aes

import "github.com/alokmenghrajani/go-cryptopals/utils"

func AesCbcDecrypt(buf, key, iv []byte) []byte {
	plaintext := []byte{}

	aes := NewAes(key)

	prev := iv
	for i := 0; i < len(buf); i += 16 {
		ciphertext := buf[i : i+16]

		// Decrypt ciphertext
		output := make([]byte, 16)
		aes.Decrypt(output, ciphertext)

		// XOR output with prev
		t := utils.Xor(output, prev)
		prev = ciphertext

		plaintext = append(plaintext, t...)

	}

	return plaintext
}

func AesCbcEncrypt(buf, key, iv []byte) []byte {
	ciphertext := []byte{}

	aes := NewAes(key)

	prev := iv
	for i := 0; i < len(buf); i += 16 {
		plaintext := buf[i : i+16]

		// XOR plaintext with prev
		input := make([]byte, 0, 16)
		for i := 0; i < 16; i++ {
			input = append(input, plaintext[i]^prev[i])
		}

		// Encrypt input
		output := make([]byte, 16)
		aes.Encrypt(output, input)
		prev = output

		ciphertext = append(ciphertext, output...)

	}

	return ciphertext
}

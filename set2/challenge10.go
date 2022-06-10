package set2

import (
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge10() {
	utils.PrintTitle(2, 10)
	file, err := os.ReadFile("set2/10.txt")
	if err != nil {
		panic(err)
	}
	input := strings.Join(strings.Split(string(file), "\n"), "")
	buf := utils.Base64ToByteSlice(input)
	buf = aesCbcDecrypt(buf, []byte("YELLOW SUBMARINE"), make([]byte, 16))
	buf, err = unpad(buf, 16)
	utils.PanicOnErr(err)
	fmt.Println(string(buf))
	fmt.Println()
}

func aesCbcDecrypt(buf, key, iv []byte) []byte {
	plaintext := []byte{}

	aes := utils.NewAes(key)

	prev := iv
	for i := 0; i < len(buf); i += 16 {
		ciphertext := buf[i : i+16]

		// Decrypt ciphertext
		output := make([]byte, 16)
		aes.Decrypt(output, ciphertext)

		// XOR output with prev
		t := make([]byte, 0, 16)
		for i := 0; i < 16; i++ {
			t = append(t, output[i]^prev[i])
		}
		prev = ciphertext

		plaintext = append(plaintext, t...)

	}

	return plaintext
}

func aesCbcEncrypt(buf, key, iv []byte) []byte {
	ciphertext := []byte{}

	aes := utils.NewAes(key)

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

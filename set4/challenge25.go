package set4

import (
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

func Challenge25() {
	utils.PrintTitle(4, 25)

	// copy-pasta from Challenge7()
	file, err := os.ReadFile("set4/25.txt")
	utils.PanicOnErr(err)
	input := strings.Join(strings.Split(string(file), "\n"), "")
	buf := base64.ToByteSlice(input)

	cipher := aes.NewAes([]byte("YELLOW SUBMARINE"))
	plaintext := []byte{}
	t := make([]byte, cipher.BlockSize())
	for i := 0; i < len(buf); i += cipher.BlockSize() {
		cipher.Decrypt(t, buf[i:i+cipher.BlockSize()])
		plaintext = append(plaintext, t...)
	}

	// encrypt output with CTR
	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	utils.PanicOnErr(err)

	aesCtr := aes.NewAesCtr(aesKey, 0)
	ciphertext := aesCtr.Process(plaintext)
	plaintext2 := breakAesCtr(ciphertext, aesKey)
	fmt.Println(string(plaintext2))

	fmt.Println()
}

func breakAesCtr(ciphertext, aesKey []byte) []byte {
	ciphertext2 := make([]byte, len(ciphertext))
	copy(ciphertext2, ciphertext)

	buf := make([]byte, len(ciphertext))
	edit(ciphertext2, aesKey, 0, buf)

	return utils.Xor(ciphertext, ciphertext2)
}

func edit(ciphertext []byte, aesKey []byte, offset int, replacement []byte) {
	aesCtr := aes.NewAesCtr(aesKey, 0)
	replacementCiphertext := aesCtr.Process(replacement)
	copy(ciphertext[offset:], replacementCiphertext)
}

package set4

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge26() {
	utils.PrintTitle(4, 26)

	// generate random AES key
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	// craft ciphertext
	ciphertext := craft(aesKey)

	// decrypt to check result
	isAdmin := decrypt(ciphertext, aesKey)
	fmt.Println(isAdmin)

	fmt.Println()
}

func encrypt(s string, aesKey []byte) []byte {
	s = strings.ReplaceAll(s, ";", "%3b")
	s = strings.ReplaceAll(s, "=", "%3d")
	s = "comment1=cooking%20MCs;userdata=" + s
	s = s + ";comment2=%20like%20a%20pound%20of%20bacon"

	aesCtr := aes.NewAesCtr(aesKey, 0)
	return aesCtr.Process([]byte(s))
}

func decrypt(ciphertext, aesKey []byte) bool {
	aesCtr := aes.NewAesCtr(aesKey, 0)
	s := string(aesCtr.Process(ciphertext))

	return utils.IsAdmin(s)
}

func craft(aesKey []byte) []byte {
	// Compared to challenge 16, this code is much simpler since we can modify exactly
	// the bytes we want.
	s := "_admin_true_x_"
	buf := encrypt(s, aesKey)

	prefix := "comment1=cooking%20MCs;userdata="
	offset := len(prefix)

	// change byte 0 from "_" to ";"
	if s[0] != '_' {
		panic("oops")
	}
	buf[offset] = buf[offset] ^ '_' ^ ';'

	// change byte 6 from "_" to "="
	if s[6] != '_' {
		panic("oops")
	}
	buf[offset+6] = buf[offset+6] ^ '_' ^ '='

	// change byte 11 from "_" to ";"
	if s[11] != '_' {
		panic("oops")
	}
	buf[offset+11] = buf[offset+11] ^ '_' ^ ';'

	// change byte 13 from "_" to "="
	if s[13] != '_' {
		panic("oops")
	}
	buf[offset+13] = buf[offset+13] ^ '_' ^ '='
	return buf
}

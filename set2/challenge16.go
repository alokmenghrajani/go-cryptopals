package set2

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge16() {
	utils.PrintTitle(2, 16)

	// generate random AES key
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	// craft ciphertext
	ciphertext := craft(aesKey)

	// decrypt to check result
	s2 := decrypt(ciphertext, aesKey)
	fmt.Println(s2)

	fmt.Println()
}

func encrypt(s string, aesKey []byte) []byte {
	s = strings.ReplaceAll(s, ";", "%3b")
	s = strings.ReplaceAll(s, "=", "%3d")
	s = "comment1=cooking%20MCs;userdata=" + s
	s = s + ";comment2=%20like%20a%20pound%20of%20bacon"

	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	utils.PanicOnErr(err)

	return append(iv, aes.AesCbcEncrypt(pkcs7.Pad([]byte(s), 16), aesKey, iv)...)
}

func decrypt(buf, aesKey []byte) bool {
	iv := buf[0:16]
	ciphertext := buf[16:]
	s := string(aes.AesCbcDecrypt(ciphertext, aesKey, iv))
	return utils.IsAdmin(s)
}

func craft(aesKey []byte) []byte {
	// if we have a ciphertext "abcdefgh" and assuming a 4-byte block cipher, we can
	// xor specific bytes in the 2nd block:
	//
	//     abcd   efgh
	//     vvvv   vvvv
	//     xyzs   rtye
	// xor ....   abcd
	//     ----   ----
	//     plai   ntex   t

	// our input string is thus going to look like:
	// [padding...][AAAAA...][BBBBB...]
	//
	// such that BBBBB is a block with "_admin_true_x_"
	// which will later become ";admin=true;x="
	prefix := "comment1=cooking%20MCs;userdata="
	l1 := utils.Remaining(len(prefix), 16)
	input := strings.Repeat("_", l1)
	s1 := strings.Repeat("_", 16)
	input += s1
	s2 := "_admin_true_x_"
	input += s2
	l2 := utils.Remaining(len(s2), 16)
	input += strings.Repeat("_", l2)
	buf := encrypt(input, aesKey)

	offset := len(prefix) + l1 + 16 // add 16 because of IV

	// change byte 0 from "_" to ";"
	if s2[0] != '_' {
		panic("oops")
	}
	buf[offset] = buf[offset] ^ '_' ^ ';'

	// change byte 6 from "_" to "="
	if s2[6] != '_' {
		panic("oops")
	}
	buf[offset+6] = buf[offset+6] ^ '_' ^ '='

	// change byte 11 from "_" to ";"
	if s2[11] != '_' {
		panic("oops")
	}
	buf[offset+11] = buf[offset+11] ^ '_' ^ ';'

	// change byte 13 from "_" to "="
	if s2[13] != '_' {
		panic("oops")
	}
	buf[offset+13] = buf[offset+13] ^ '_' ^ '='
	return buf
}

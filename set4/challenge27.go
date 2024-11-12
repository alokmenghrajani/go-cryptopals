package set4

import (
	"fmt"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/pkg/errors"
)

func Challenge27(rng *rng.Rng) {
	utils.PrintTitle(4, 27)

	// generate random AES key
	aesKey := rng.Bytes(aes.KeySize)

	// encrypt some random text
	plaintext := "Beyond the cold winter. A purple dinosaur roars. Melting the snowmen."
	ciphertext := encryptWithIvEquKey(plaintext, aesKey)

	// recover the key
	buf := make([]byte, len(ciphertext))
	copy(buf, ciphertext[0:16])
	copy(buf[32:48], ciphertext[0:16])
	copy(buf[48:], ciphertext[48:])

	plaintext2, err := decryptWithIvEquKey(buf, aesKey)
	var buf2 []byte
	if err != nil {
		s := err.Error()
		prefix := "invalid plaintext: "
		if strings.HasPrefix(s, prefix) {
			buf2 = hex.ToByteSlice(s[len(prefix):])
		} else {
			panic(err)
		}
	} else {
		buf2 = []byte(plaintext2)
	}

	key := utils.Xor(buf2[0:16], buf2[32:48])
	fmt.Printf("original key: %x\n", aesKey)
	fmt.Printf("cracked key:  %x\n", key)

	fmt.Println()
}

func encryptWithIvEquKey(plaintext string, aesKey []byte) []byte {
	for i := 0; i < len(plaintext); i++ {
		if plaintext[i] >= 128 {
			panic("invalid plaintext")
		}
	}
	return aes.AesCbcEncrypt(pkcs7.Pad([]byte(plaintext), aes.BlockSize), aesKey, aesKey)
}

func decryptWithIvEquKey(ciphertext, aesKey []byte) (string, error) {
	plaintext := aes.AesCbcDecrypt(ciphertext, aesKey, aesKey)
	plaintext, err := pkcs7.Unpad(plaintext, aes.BlockSize)
	if err != nil {
		return "", err
	}

	for i := 0; i < len(plaintext); i++ {
		if plaintext[i] >= 128 {
			return "", errors.Errorf("invalid plaintext: %x", plaintext)
		}
	}
	return string(plaintext), nil
}

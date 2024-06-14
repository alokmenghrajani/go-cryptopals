package aes

import (
	"crypto/rand"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/stretchr/testify/require"
)

func TestCbcEncryptionDecryption(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	utils.PanicOnErr(err)

	iv := make([]byte, BlockSize)
	_, err = rand.Read(key)
	utils.PanicOnErr(err)

	expected := []byte("hello world")
	ciphertext := AesCbcEncrypt(pkcs7.Pad(expected, BlockSize), key, iv)
	plaintext, err := pkcs7.Unpad(AesCbcDecrypt(ciphertext, key, iv), BlockSize)
	utils.PanicOnErr(err)

	require.Equal(t, expected, plaintext)
}

package set2

import (
	"crypto/rand"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/stretchr/testify/require"
)

func TestCbcEncryptionDecryption(t *testing.T) {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	utils.PanicOnErr(err)

	iv := make([]byte, 16)
	_, err = rand.Read(key)
	utils.PanicOnErr(err)

	expected := []byte("hello world")
	ciphertext := AesCbcEncrypt(Pad(expected, 16), key, iv)
	plaintext, err := Unpad(AesCbcDecrypt(ciphertext, key, iv), 16)
	require.Nil(t, err)
	require.Equal(t, expected, plaintext)
}

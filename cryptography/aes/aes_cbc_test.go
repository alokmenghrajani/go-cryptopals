package aes

import (
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/require"
)

func TestCbcEncryptionDecryption(t *testing.T) {
	rng := rng.New()
	key := rng.Bytes(KeySize)
	iv := rng.Bytes(BlockSize)

	expected := []byte("hello world")
	ciphertext := AesCbcEncrypt(pkcs7.Pad(expected, BlockSize), key, iv)
	plaintext, err := pkcs7.Unpad(AesCbcDecrypt(ciphertext, key, iv), BlockSize)
	require.Nil(t, err)
	require.Equal(t, expected, plaintext)
}

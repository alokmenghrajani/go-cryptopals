package aes

import (
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/require"
)

func TestAesCtr(t *testing.T) {
	rng := rng.New()

	plaintext := "hello world"
	aesKey := rng.Bytes(KeySize)
	nonce := rng.Uint64()

	aesCtr := NewAesCtr(aesKey, nonce)
	ciphertext := aesCtr.Process([]byte(plaintext))

	aesCtr = NewAesCtr(aesKey, nonce)
	plaintext2 := string(aesCtr.Process(ciphertext))

	require.Equal(t, plaintext, plaintext2)
}

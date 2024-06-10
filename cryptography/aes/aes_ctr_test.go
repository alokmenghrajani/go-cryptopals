package aes

import (
	"crypto/rand"
	insecureRand "math/rand"
	"testing"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/stretchr/testify/require"
)

func TestAesCtr(t *testing.T) {
	seed := time.Now().Unix()
	insecureRand.Seed(seed)

	plaintext := "hello world"

	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	nonce := insecureRand.Uint64()

	aesCtr := NewAesCtr(aesKey, nonce)
	ciphertext := aesCtr.Process([]byte(plaintext))

	aesCtr = NewAesCtr(aesKey, nonce)
	plaintext2 := string(aesCtr.Process(ciphertext))

	require.Equal(t, plaintext, plaintext2, seed)
}

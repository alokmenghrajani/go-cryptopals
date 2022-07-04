package utils

import (
	"crypto/hmac"
	refSha256 "crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHmacSha256(t *testing.T) {
	h := HmacSha256([]byte("key"), []byte("The quick brown fox jumps over the lazy dog"))
	require.Equal(t, HexToByteSlice("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"), h)

	h = HmacSha256([]byte("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog"), []byte("message"))
	require.Equal(t, HexToByteSlice("5597b93a2843078cbb0c920ae41dfe20f1685e10c67e423c11ab91adfc319d12"), h)

	for i := 1; i < 100; i++ {
		key := make([]byte, i)
		_, err := rand.Read(key)
		PanicOnErr(err)
		msg := []byte("hello world")
		h = HmacSha256(key, msg)

		mac := hmac.New(refSha256.New, key)
		mac.Write(msg)
		require.Equal(t, mac.Sum(nil), h, fmt.Sprintf("key=%02x", key))
	}
}

package utils

import (
	"crypto/hmac"
	refSha1 "crypto/sha1"
	"fmt"
	"math/rand"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/stretchr/testify/require"
)

func TestHmacSha1(t *testing.T) {
	h := HmacSha1([]byte("key"), []byte("The quick brown fox jumps over the lazy dog"))
	require.Equal(t, hex.ToByteSlice("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"), h)

	for i := 1; i < 100; i++ {
		key := make([]byte, i)
		_, err := rand.Read(key)
		PanicOnErr(err)
		msg := []byte("hello world")
		h = HmacSha1(key, msg)

		mac := hmac.New(refSha1.New, key)
		mac.Write(msg)
		require.Equal(t, mac.Sum(nil), h, fmt.Sprintf("key=%02x", key))
	}
}

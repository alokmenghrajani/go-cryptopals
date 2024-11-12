package hmacSha1

import (
	"crypto/hmac"
	refSha1 "crypto/sha1"
	"fmt"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/require"
)

func TestCompute(t *testing.T) {
	rng := rng.New()

	h := Compute([]byte("key"), []byte("The quick brown fox jumps over the lazy dog"))
	require.Equal(t, hex.ToByteSlice("de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"), h)

	for i := 1; i < 100; i++ {
		key := rng.Bytes(i)
		msg := []byte("hello world")
		h = Compute(key, msg)

		mac := hmac.New(refSha1.New, key)
		mac.Write(msg)
		require.Equal(t, mac.Sum(nil), h, fmt.Sprintf("key=%02x", key))
	}
}

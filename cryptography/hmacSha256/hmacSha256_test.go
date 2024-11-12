package hmacSha256

import (
	"crypto/hmac"
	refSha256 "crypto/sha256"
	"fmt"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/require"
)

func TestCompute(t *testing.T) {
	rng := rng.New()

	h := Compute([]byte("key"), []byte("The quick brown fox jumps over the lazy dog"))
	require.Equal(t, hex.ToByteSlice("f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"), h)

	h = Compute([]byte("The quick brown fox jumps over the lazy dogThe quick brown fox jumps over the lazy dog"), []byte("message"))
	require.Equal(t, hex.ToByteSlice("5597b93a2843078cbb0c920ae41dfe20f1685e10c67e423c11ab91adfc319d12"), h)

	for i := 1; i < 100; i++ {
		key := rng.Bytes(i)
		msg := []byte("hello world")
		h = Compute(key, msg)

		mac := hmac.New(refSha256.New, key)
		mac.Write(msg)
		require.Equal(t, mac.Sum(nil), h, fmt.Sprintf("key=%02x", key))
	}
}

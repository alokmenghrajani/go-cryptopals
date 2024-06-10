package rc4

import (
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/stretchr/testify/require"
)

// Check conformance of rc4 with test vectors from https://en.wikipedia.org/wiki/RC4
func TestProcess(t *testing.T) {
	rc4 := New([]byte("Key"))
	ciphertext := rc4.Process([]byte("Plaintext"))
	require.Equal(t, hex.ToByteSlice("bbf316e8d940af0ad3"), ciphertext)

	rc4 = New([]byte("Wiki"))
	ciphertext = rc4.Process([]byte("pedia"))
	require.Equal(t, hex.ToByteSlice("1021bf0420"), ciphertext)

	rc4 = New([]byte("Secret"))
	ciphertext = rc4.Process([]byte("Attack at dawn"))
	require.Equal(t, hex.ToByteSlice("45a01f645fc35b383552544b9bf5"), ciphertext)
}

package sha256

import (
	refSha "crypto/sha256"
	"fmt"
	"math/rand"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/stretchr/testify/require"
)

func TestSha256(t *testing.T) {
	s := New()
	s.Update([]byte("hello world"))
	hash := hex.FromByteSlice(s.Digest())
	require.Equal(t, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hash)

	s = New()
	s.Update([]byte("abc"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash)

	s = New()
	s.Update([]byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", hash)

	s = New()
	for i := 0; i < 1000000; i++ {
		s.Update([]byte("a"))
	}
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", hash)

	s = New()
	for i := 0; i < 80; i++ {
		s.Update([]byte("01234567"))
	}
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "594847328451bdfa85056225462cc1d867d877fb388df0ce35f25ab5562bfbb5", hash)

	s = New()
	s.Update([]byte("\x19"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "68aa2e2ee5dff96e3355e6c7ee373e3d6a4e17f75f9518d843709c0c9bc3e3d4", hash)

	s = New()
	s.Update([]byte("\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "175ee69b02ba9b58e2b0a5fd13819cea573f3940a94f825128cf4209beabb4e8", hash)

	s = New()
	s.Update([]byte(
		"\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0" +
			"\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00" +
			"\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77" +
			"\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74" +
			"\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b" +
			"\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca" +
			"\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4" +
			"\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09" +
			"\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a" +
			"\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39" +
			"\x3d\x54\xd6"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "97dbca7df46d62c8a422c941dd7e835b8ad3361763f7e9b2d95f4f0da6e1ccbc", hash)

	// compare result with crypto/sha256
	for i := 0; i < 10000; i++ {
		buf := make([]byte, i)
		_, err := rand.Read(buf)
		utils.PanicOnErr(err)

		s = New()
		s.Update(buf)
		r := refSha.Sum256(buf)
		require.Equal(t, r[:], s.Digest(), fmt.Sprintf("i=%q", buf))
	}
}

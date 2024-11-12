package sha1

import (
	refSha "crypto/sha1"
	"fmt"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/require"
)

func TestSha1Padding(t *testing.T) {
	s := New()
	s.Update([]byte("abcde"))
	s.pad()

	require.Equal(t, []byte{
		0x61, 0x62, 0x63, 0x64,
		0x65, 0x80, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x28}, s.buf)
}

func TestSha1(t *testing.T) {
	rng := rng.New()

	s := New()
	s.Update([]byte("hello world"))
	hash := hex.FromByteSlice(s.Digest())
	require.Equal(t, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed", hash)

	s = New()
	s.Update([]byte("abc"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "a9993e364706816aba3e25717850c26c9cd0d89d", hash)

	s = New()
	s.Update([]byte("x"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "11f6ad8ec52a2984abaafd7c3b516503785c2072", hash)

	s = New()
	s.Update([]byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "84983e441c3bd26ebaae4aa1f95129e5e54670f1", hash)

	s = New()
	for i := 0; i < 1000000; i++ {
		s.Update([]byte("a"))
	}
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "34aa973cd4c4daa4f61eeb2bdbad27316534016f", hash)

	s = New()
	for i := 0; i < 80; i++ {
		s.Update([]byte("01234567"))
	}
	hash = hex.FromByteSlice(s.Digest())
	require.Equal(t, "dea356a2cddd90c7a7ecedc5ebb563934f460452", hash)

	// compare result with crypto/sha1
	for i := 0; i < 10000; i++ {
		buf := rng.Bytes(i)
		s = New()
		s.Update(buf)
		r := refSha.Sum(buf)
		require.Equal(t, r[:], s.Digest(), fmt.Sprintf("i=%q", buf))
	}
}

package utils

import (
	"fmt"
	"math/rand"
	"testing"

	refMd4 "golang.org/x/crypto/md4"

	"github.com/stretchr/testify/require"
)

func TestMd4Padding(t *testing.T) {
	s := NewMd4()
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
		0x28, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00}, s.buf)
}

func TestMd4(t *testing.T) {
	s := NewMd4()
	s.Update([]byte(""))
	hash := ByteSliceToHex(s.Digest())
	require.Equal(t, "31d6cfe0d16ae931b73c59d7e0c089c0", hash)

	s = NewMd4()
	s.Update([]byte("a"))
	hash = ByteSliceToHex(s.Digest())
	require.Equal(t, "bde52cb31de33e46245e05fbdbd6fb24", hash)

	s = NewMd4()
	s.Update([]byte("abc"))
	hash = ByteSliceToHex(s.Digest())
	require.Equal(t, "a448017aaf21d8525fc10ae87aa6729d", hash)

	s = NewMd4()
	s.Update([]byte("message digest"))
	hash = ByteSliceToHex(s.Digest())
	require.Equal(t, "d9130a8164549fe818874806e1c7014b", hash)

	s = NewMd4()
	s.Update([]byte("abcdefghijklmnopqrstuvwxyz"))
	hash = ByteSliceToHex(s.Digest())
	require.Equal(t, "d79e1c308aa5bbcdeea8ed63df412da9", hash)

	s = NewMd4()
	s.Update([]byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"))
	hash = ByteSliceToHex(s.Digest())
	require.Equal(t, "043f8582f241db351ce627e153e7f0e4", hash)

	s = NewMd4()
	s.Update([]byte("12345678901234567890123456789012345678901234567890123456789012345678901234567890"))
	hash = ByteSliceToHex(s.Digest())
	require.Equal(t, "e33b4ddc9c38f2199c3e7b164fcc0536", hash)

	// compare result with x/crypto/md4
	for i := 0; i < 10000; i++ {
		buf := make([]byte, i)
		_, err := rand.Read(buf)
		PanicOnErr(err)

		s = NewMd4()
		s.Update(buf)
		r := refMd4.New()
		r.Write(buf)
		r2 := r.Sum([]byte{})
		require.Equal(t, r2, s.Digest(), fmt.Sprintf("i=%q", buf))
	}
}

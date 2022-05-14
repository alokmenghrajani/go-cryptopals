package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitsToBase64(t *testing.T) {
	require.Equal(t, byte('B'), bitsToBase64(1))
	require.Equal(t, byte('m'), bitsToBase64(38))
	require.Equal(t, byte('4'), bitsToBase64(56))
	require.Equal(t, byte('+'), bitsToBase64(62))
	require.Equal(t, byte('/'), bitsToBase64(63))
}

func TestByteSliceToBase64(t *testing.T) {
	require.Equal(t, "", ByteSliceToBase64([]byte("")))
	require.Equal(t, "Zg==", ByteSliceToBase64([]byte("f")))
	require.Equal(t, "Zm8=", ByteSliceToBase64([]byte("fo")))
	require.Equal(t, "Zm9v", ByteSliceToBase64([]byte("foo")))
	require.Equal(t, "Zm9vYg==", ByteSliceToBase64([]byte("foob")))
	require.Equal(t, "Zm9vYmE=", ByteSliceToBase64([]byte("fooba")))
	require.Equal(t, "Zm9vYmFy", ByteSliceToBase64([]byte("foobar")))
}

func TestBase64ToByteSlice(t *testing.T) {
	require.Equal(t, []byte(""), Base64ToByteSlice(""))
	require.Equal(t, []byte("f"), Base64ToByteSlice("Zg=="))
	require.Equal(t, []byte("fo"), Base64ToByteSlice("Zm8="))
	require.Equal(t, []byte("foo"), Base64ToByteSlice("Zm9v"))
	require.Equal(t, []byte("foob"), Base64ToByteSlice("Zm9vYg=="))
	require.Equal(t, []byte("fooba"), Base64ToByteSlice("Zm9vYmE="))
	require.Equal(t, []byte("foobar"), Base64ToByteSlice("Zm9vYmFy"))
}

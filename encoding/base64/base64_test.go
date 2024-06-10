package base64

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

func TestFromByteSlice(t *testing.T) {
	require.Equal(t, "", FromByteSlice([]byte("")))
	require.Equal(t, "Zg==", FromByteSlice([]byte("f")))
	require.Equal(t, "Zm8=", FromByteSlice([]byte("fo")))
	require.Equal(t, "Zm9v", FromByteSlice([]byte("foo")))
	require.Equal(t, "Zm9vYg==", FromByteSlice([]byte("foob")))
	require.Equal(t, "Zm9vYmE=", FromByteSlice([]byte("fooba")))
	require.Equal(t, "Zm9vYmFy", FromByteSlice([]byte("foobar")))
}

func TestToByteSlice(t *testing.T) {
	require.Equal(t, []byte(""), ToByteSlice(""))
	require.Equal(t, []byte("f"), ToByteSlice("Zg=="))
	require.Equal(t, []byte("fo"), ToByteSlice("Zm8="))
	require.Equal(t, []byte("foo"), ToByteSlice("Zm9v"))
	require.Equal(t, []byte("foob"), ToByteSlice("Zm9vYg=="))
	require.Equal(t, []byte("fooba"), ToByteSlice("Zm9vYmE="))
	require.Equal(t, []byte("foobar"), ToByteSlice("Zm9vYmFy"))
}

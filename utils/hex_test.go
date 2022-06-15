package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHexToNibble(t *testing.T) {
	require.Equal(t, byte(1), hexToNibble('1'))
	require.Equal(t, byte(10), hexToNibble('a'))
	require.Equal(t, byte(15), hexToNibble('f'))
}

func TestHexToByte(t *testing.T) {
	require.Equal(t, byte(26), hexToByte("1a"))
	require.Equal(t, byte(17), hexToByte("11"))
	require.Equal(t, byte(42), hexToByte("2a"))
}

func TestHexToByteSlice(t *testing.T) {
	require.Equal(t, []byte{0x49, 0x27, 0x6d, 0x20}, HexToByteSlice("49276d20"))
}

func TestNibbleToHex(t *testing.T) {
	require.Equal(t, byte('1'), nibbleToHex(1))
	require.Equal(t, byte('a'), nibbleToHex(10))
	require.Equal(t, byte('f'), nibbleToHex(15))
}

func TestByteToHex(t *testing.T) {
	require.Equal(t, "1a", byteToHex(26))
	require.Equal(t, "11", byteToHex(17))
	require.Equal(t, "2a", byteToHex(42))
}

func TestByteSliceToHex(t *testing.T) {
	require.Equal(t, "49276d20", ByteSliceToHex([]byte{0x49, 0x27, 0x6d, 0x20}))
}

package set1

import (
	"testing"

	"github.com/stretchr/testify/require"
)

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
	require.Equal(t, "49276d20", byteSliceToHex([]byte{0x49, 0x27, 0x6d, 0x20}))
}

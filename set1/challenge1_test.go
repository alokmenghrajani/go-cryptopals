package set1

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
	require.Equal(t, []byte{0x49, 0x27, 0x6d, 0x20}, hexToByteSlice("49276d20"))
}

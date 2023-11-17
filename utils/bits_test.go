package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRotateLeft(t *testing.T) {
	v := uint32(0x85555d69)
	require.Equal(t, uint32(0xaaabad3), RotateLeft(v, 1))
	require.Equal(t, uint32(0x155575a6), RotateLeft(v, 2))
	require.Equal(t, uint32(0x2aaaeb4c), RotateLeft(v, 3))
	require.Equal(t, uint32(0x5555d698), RotateLeft(v, 4))
	require.Equal(t, uint32(0xaaabad30), RotateLeft(v, 5))
}

func TestRotateRight(t *testing.T) {
	v := uint32(0xe54d5360)
	require.Equal(t, uint32(0x72a6a9b0), RotateRight(v, 1))
	require.Equal(t, uint32(0x395354d8), RotateRight(v, 2))
	require.Equal(t, uint32(0x1ca9aa6c), RotateRight(v, 3))
	require.Equal(t, uint32(0xe54d536), RotateRight(v, 4))
	require.Equal(t, uint32(0x72a6a9b), RotateRight(v, 5))
	require.Equal(t, uint32(0x8395354d), RotateRight(v, 6))
}

package big

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRoot(t *testing.T) {
	x := NewInt(64).Root(2)
	require.Equal(t, "8", x.String())

	x = FromBytes([]byte{0xec, 0x34, 0x1a, 0xf5, 0x01, 0x72, 0x4b, 0x0c, 0x80})
	x = x.Root(7)
	require.Equal(t, "1234", x.String())
}

package bigutils

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMax(t *testing.T) {
	a := big.NewInt(123)
	b := big.NewInt(456)
	c := Max(a, b)
	require.Equal(t, b, c)

	c = Max(b, a)
	require.Equal(t, b, c)
}

func TestMin(t *testing.T) {
	a := big.NewInt(123)
	b := big.NewInt(456)
	c := Min(a, b)
	require.Equal(t, a, c)

	c = Min(b, a)
	require.Equal(t, a, c)
}

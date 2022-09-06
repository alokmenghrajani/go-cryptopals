package big

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRandN4bit(t *testing.T) {
	for i := 1; i < 250; i++ {
		n := NewInt(int64(i))
		for j := 0; j < i; j++ {
			target := fmt.Sprintf("%d", j)
			for {
				r := Randn(n)
				if r.String() == target {
					break
				}
			}
		}
	}
}

func TestRandnParams4bit(t *testing.T) {
	// 1 is a bit of a special case. The mask should be 0x01 instead of 0x0f.
	l, mask := randnParams(One)
	require.Equal(t, 1, l)
	require.Equal(t, byte(0x01), mask)

	for i := 2; i <= 2048; i++ {
		n := NewInt(int64(i))
		l, mask = randnParams(n)
		require.True(t, mask == 0 || mask == 1 || mask == 3 || mask == 7 || mask == 15, fmt.Sprintf("i=%d", i))

		m := n.v[len(n.v)-1]
		// there are two cases, depending if i is of the form 0b100..00 or not
		if countBits(i) == 1 {
			nminus1 := NewInt(int64(i - 1))
			require.Equal(t, len(nminus1.v), l, fmt.Sprintf("i=%d", i))
			if m == 1 {
				require.Equal(t, byte(0xf), mask, fmt.Sprintf("i=%d", i))
			} else {
				require.Equal(t, m, mask+1, fmt.Sprintf("i=%d", i))
			}
		} else {
			require.Equal(t, len(n.v), l, fmt.Sprintf("i=%d", i))
			require.Equal(t, m, m&mask, fmt.Sprintf("i=%d", i))
			require.NotEqual(t, m, m&(mask>>1), fmt.Sprintf("i=%d", i))
		}
	}
}

func countBits(n int) int {
	r := 0
	for n != 0 {
		n = n & (n - 1)
		r++
	}
	return r
}

package big

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCmp4bit(t *testing.T) {
	for i := -2048; i <= 2048; i++ {
		n1 := NewInt(int64(i))
		for j := -2048; j <= 2048; j++ {
			n2 := NewInt(int64(j))
			c := n1.Cmp(n2)

			expected := 0
			if i < j {
				expected = -1
			} else if i > j {
				expected = 1
			}
			require.Equal(t, expected, c)
		}
	}
}

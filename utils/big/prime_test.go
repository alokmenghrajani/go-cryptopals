package big

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProbablyPrime(t *testing.T) {
	// 7069 is a prime number
	r := NewInt(7069).ProbablyPrime()
	require.True(t, r)

	// 561 is a Carmichael number but we use 3 for one of the four rounds of
	// checks, so 561 won't be a false positive.
	// 561 = 3 * 11 * 17
	r = NewInt(561).ProbablyPrime()
	require.False(t, r)

	// 29341 is a Carmichael number, we expect a false positive
	// 29341 = 13 * 37 * 61
	r = NewInt(29341).ProbablyPrime()
	require.True(t, r)

	// 143 is composite and isn't a Carmichael number
	// 11 * 13
	r = NewInt(143).ProbablyPrime()
	require.False(t, r)
}

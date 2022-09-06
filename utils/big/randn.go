package big

import (
	"crypto/rand"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// Randn returns a randomly generated number between 0 (included) and n (excluded).
// I.e in the range [0, n). Panics if n <= 0.
func Randn(n *Int) *Int {
	l, mask := randnParams(n)
	buf := make([]byte, l)
	for {
		_, err := rand.Read(buf)
		utils.PanicOnErr(err)

		buf[0] = buf[0] & mask
		x := FromBytes(buf)
		if x.Cmp(n) != -1 {
			continue
		}
		return x
	}
}

func randnParams(n *Int) (int, byte) {
	if n.Cmp(Zero) != 1 {
		panic("n is zero or negative")
	}
	nminus1 := n.Sub(One)
	t := nminus1.Msb()
	l := (t / W) + 1

	// create a mask for the top most element
	t = t % W
	mask := byte((1 << (t + 1)) - 1)

	return l, mask
}

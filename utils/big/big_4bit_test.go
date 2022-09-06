package big

import (
	"fmt"
	originalBig "math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

// Exhaustive testing using 4-bit implementation

func Test4BitNewInt(t *testing.T) {
	n := NewInt(int64(0x65))
	require.Equal(t, []byte{0x05, 0x06}, n.v)

	n = NewInt(-1234)
	require.Equal(t, []byte{0x02, 0x0d, 0x04}, n.v)
}

func Test4BitString(t *testing.T) {
	for x := -4096; x <= 4096; x++ {
		n := NewInt(int64(x))
		require.Equal(t, fmt.Sprintf("%d", x), n.String())
	}
}

func TestAdd4Bit(t *testing.T) {
	for x := 0; x <= 4096; x++ {
		n1 := NewInt(int64(x))
		for y := -2048; y <= 4096; y++ {
			n2 := NewInt(int64(y))
			sum := n1.Add(n2)
			require.Equal(t, fmt.Sprintf("%d", x+y), sum.String(), fmt.Sprintf("x: %d, y: %d", x, y))
		}
	}
}

func TestSub4Bit(t *testing.T) {
	for x := -2048; x <= 2048; x++ {
		n1 := NewInt(int64(x))
		for y := -2048; y <= 2048; y++ {
			n2 := NewInt(int64(y))
			diff := n1.Sub(n2)
			require.Equal(t, fmt.Sprintf("%d", x-y), diff.String(), fmt.Sprintf("x: %d, y: %d", x, y))
		}
	}
}

func TestMul4Bit(t *testing.T) {
	for x := -2048; x <= 2048; x++ {
		n1 := NewInt(int64(x))
		for y := -2048; y <= 2048; y++ {
			n2 := NewInt(int64(y))
			product := n1.Mul(n2)
			require.Equal(t, fmt.Sprintf("%d", x*y), product.String(), fmt.Sprintf("x: %d, y: %d", x, y))
		}
	}
}

func TestDiv4BitPart1(t *testing.T) {
	for x := -2048; x < 0; x++ {
		nn1 := NewInt(int64(x))
		n1 := originalBig.NewInt(int64(x))
		for y := -2048; y <= 2048; y++ {
			if y == 0 {
				continue
			}
			nn2 := NewInt(int64(y))
			n2 := originalBig.NewInt(int64(y))

			qq, rr := nn1.Div(nn2)
			q := &originalBig.Int{}
			q.Div(n1, n2)
			r := &originalBig.Int{}
			r.Mod(n1, n2)

			require.Equal(t, q.String(), qq.String(), fmt.Sprintf("x: %d, y: %d", x, y))
			require.Equal(t, r.String(), rr.String(), fmt.Sprintf("x: %d, y: %d", x, y))
		}
	}
}

func TestDiv4BitPart2(t *testing.T) {
	for x := 0; x <= 2048; x++ {
		n1 := NewInt(int64(x))
		for y := -2048; y <= 2048; y++ {
			if y == 0 {
				continue
			}
			n2 := NewInt(int64(y))
			q, r := n1.Div(n2)
			require.Equal(t, fmt.Sprintf("%d", x/y), q.String(), fmt.Sprintf("x: %d, y: %d", x, y))
			require.Equal(t, fmt.Sprintf("%d", x%y), r.String(), fmt.Sprintf("x: %d, y: %d", x, y))
		}
	}
}

func TestExpMod4Bit(t *testing.T) {
	for x := -128; x <= 256; x++ {
		nn1 := NewInt(int64(x))
		n1 := originalBig.NewInt(int64(x))
		for y := 0; y <= 64; y++ {
			nn2 := NewInt(int64(y))
			n2 := originalBig.NewInt(int64(y))
			for z := -20; z <= 20; z++ {
				if z == 0 {
					continue
				}
				nn3 := NewInt(int64(z))
				n3 := originalBig.NewInt(int64(z))

				rr := nn1.ExpMod(nn2, nn3)
				r := &originalBig.Int{}
				r.Exp(n1, n2, n3)

				require.Equal(t, r.String(), rr.String(), fmt.Sprintf("x: %d, y: %d, z: %d", x, y, z))
			}
		}
	}
}

func TestExtendedGCD4Bit(t *testing.T) {
	for a := 1; a <= 2048; a++ {
		nn1 := NewInt(int64(a))
		n1 := originalBig.NewInt(int64(a))
		for b := 1; b <= 2048; b++ {
			nn2 := NewInt(int64(b))
			n2 := originalBig.NewInt(int64(b))

			x := &originalBig.Int{}
			y := &originalBig.Int{}
			g := &originalBig.Int{}
			g.GCD(x, y, n1, n2)

			gg, xx, yy := nn1.ExtendedGCD(nn2)

			require.Equal(t, g.String(), gg.String(), fmt.Sprintf("a: %d, b: %d", a, b))
			require.Equal(t, x.String(), xx.String(), fmt.Sprintf("a: %d, b: %d", a, b))
			require.Equal(t, y.String(), yy.String(), fmt.Sprintf("a: %d, b: %d", a, b))
		}
	}
}

func TestModInverse4Bit(t *testing.T) {
	for x := 1; x <= 2048; x++ {
		nn1 := NewInt(int64(x))
		n1 := originalBig.NewInt(int64(x))
		for m := 1; m <= 2048; m++ {
			nn2 := NewInt(int64(m))
			n2 := originalBig.NewInt(int64(m))

			i := &originalBig.Int{}
			i = i.ModInverse(n1, n2)

			ii := nn1.ModInverse(nn2)
			if i == nil {
				require.Nil(t, ii, fmt.Sprintf("x: %d, m: %d", x, m))
			} else {
				require.Equal(t, i.String(), ii.String(), fmt.Sprintf("x: %d, m: %d", x, m))
			}
		}
	}
}

func TestMeh2(t *testing.T) {
	n1 := originalBig.NewInt(3)
	n2 := originalBig.NewInt(10)
	n1 = n1.ModInverse(n1, n2)
	fmt.Printf("n1: %s\n", n1.String())

	nn1 := NewInt(3)
	nn2 := NewInt(10)
	r := nn1.ModInverse(nn2)
	fmt.Printf("r: %s\n", r.String())

	nn1 = NewInt(3)
	nn2 = NewInt(10)
	gg, xx, yy := nn1.ExtendedGCD(nn2)
	fmt.Printf("gg: %s, xx: %s, yy: %s\n", gg.String(), xx.String(), yy.String())

	n1 = originalBig.NewInt(3)
	n2 = originalBig.NewInt(10)
	r2 := &originalBig.Int{}
	x2 := &originalBig.Int{}
	y2 := &originalBig.Int{}
	r2.GCD(x2, y2, n1, n2)

	fmt.Printf("r2: %s, x2: %s, y2: %s\n", r2.String(), x2.String(), y2.String())
	fmt.Println()
	// division returns leading zeros in remainder
	// e.g. 240.Div(46)
}

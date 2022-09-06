package big

import (
	"fmt"
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/stretchr/testify/require"
)

func TestNewInt(t *testing.T) {
	x := NewInt(1234)
	require.Equal(t, "1234", x.String())

	x = NewInt(-1234)
	require.Equal(t, "-1234", x.String())
}

func TestNormalize4bit(t *testing.T) {
	x := FromBytes([]byte{0x00, 0x00, 0x01, 0x00})
	require.Equal(t, 3, len(x.v))

	x = x.Sub(One)
	require.Equal(t, 2, len(x.v))

	for i := 0; i < 4; i++ {
		x.shiftRight()
	}
	require.Equal(t, 1, len(x.v))

	x = x.Sub(NewInt(16))
	x = x.Mul(Zero)
	require.False(t, x.neg)

	q, r := Zero.Div(NewInt(-1))
	require.False(t, q.neg)
	require.False(t, r.neg)
}

func TestAdd(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)
	fmt.Printf("seed=%d\n", seed)

	for i := 0; i < 1000; i++ {
		n1, nn1 := randomPair(20)
		n2, nn2 := randomPair(20)
		sum := &big.Int{}
		sum.Add(n1, n2)

		require.Equal(t, sum.String(), nn1.Add(nn2).String())
	}
}

func TestSub(t *testing.T) {
	buf1 := utils.HexToByteSlice("02ffffffffffffffff0000000000000000")
	n1 := &big.Int{}
	n1.SetBytes(buf1)
	nn1 := FromBytes(buf1)

	buf2 := utils.HexToByteSlice("01ffffffffffffffff0000000000000001")
	n2 := &big.Int{}
	n2.SetBytes(buf2)
	nn2 := FromBytes(buf2)

	s := &big.Int{}
	s.Sub(n1, n2)
	require.Equal(t, s.String(), nn1.Sub(nn2).String())

	buf1 = utils.HexToByteSlice("0200000000000000000000000000000000")
	n1 = &big.Int{}
	n1.SetBytes(buf1)
	nn1 = FromBytes(buf1)

	buf2 = utils.HexToByteSlice("0100000000000000000000000000000001")
	n2 = &big.Int{}
	n2.SetBytes(buf2)
	nn2 = FromBytes(buf2)

	s = &big.Int{}
	s.Sub(n1, n2)
	require.Equal(t, s.String(), nn1.Sub(nn2).String())

	seed := time.Now().Unix()
	rand.Seed(seed)
	fmt.Printf("seed=%d\n", seed)

	for i := 0; i < 1000; i++ {
		n1, nn1 := randomPair(20)
		n2, nn2 := randomPair(20)
		d := &big.Int{}
		d.Sub(n1, n2)

		var dd *Int
		if d.Sign() == -1 {
			dd = nn2.Sub(nn1)
			d.Abs(d)
		} else {
			dd = nn1.Sub(nn2)
		}

		require.Equal(t, d.String(), dd.String(), fmt.Sprintf("seed=%d", seed))
	}
}

func TestMul(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)
	fmt.Printf("seed=%d\n", seed)

	for i := 0; i < 1000; i++ {
		n1, nn1 := randomPair(20)
		n2, nn2 := randomPair(20)
		product := &big.Int{}
		product.Mul(n1, n2)

		require.Equal(t, product.String(), nn1.Mul(nn2).String())
	}
}

func TestDiv(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)
	fmt.Printf("seed=%d\n", seed)

	for i := 0; i < 1000; i++ {
		n1, nn1 := randomPair(30)
		n2, nn2 := randomPair(30)
		if nn2.IsZero() {
			// don't attempt division by zero
			continue
		}

		q := &big.Int{}
		q.Div(n1, n2)

		r := &big.Int{}
		r.Mod(n1, n2)

		qq, rr := nn1.Div(nn2)

		require.Equal(t, q.String(), qq.String())
		require.Equal(t, r.String(), rr.String())
	}
}

func TestExpMod(t *testing.T) {
	nn1 := FromBytes(utils.HexToByteSlice("fffffffffffffffff000000000000027"))
	nn2 := NewInt(2)
	ee := nn1.ExpMod(nn2, nn1)

	n1 := &big.Int{}
	n1.SetBytes(nn2.Bytes())
	n2 := big.NewInt(2)
	e := &big.Int{}
	e.Exp(n1, n2, n1)

	require.Equal(t, e.String(), ee.String())
}

func TestIsZero(t *testing.T) {
	require.True(t, Zero.IsZero())
	require.False(t, One.IsZero())
	require.False(t, FromBytes([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).IsZero())
}

func TestCmp(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)
	fmt.Printf("seed=%d\n", seed)

	for i := 0; i < 1000; i++ {
		n1, nn1 := randomPair(20)
		n2, nn2 := randomPair(20)
		c := n1.Cmp(n2)
		require.Equal(t, c, nn1.Cmp(nn2))
	}
}

func TestString(t *testing.T) {
	require.Equal(t, "0", Zero.String())
	require.Equal(t, "1", One.String())
	require.Equal(t, "18446744073709551616", FromBytes([]byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}).String())
}

func TestBytes(t *testing.T) {
	x := FromBytes([]byte{0x01, 0x02})
	x = x.Add(One)
	require.Equal(t, []byte{0x01, 0x03}, x.Bytes())

	require.Equal(t, []byte{0x00}, Zero.Bytes())
}

func TestShiftLeft(t *testing.T) {
	x := NewInt(123)
	x.shiftLeft()
	require.Equal(t, "246", x.String())
	for i := 0; i < 70; i++ {
		x.shiftLeft()
	}
	require.Equal(t, "290425538696483180642304", x.String())
}

func TestShiftRight(t *testing.T) {
	x := NewInt(123)
	x.shiftRight()
	require.Equal(t, "61", x.String())
	x = FromBytes([]byte{0x3d, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for i := 0; i < 71; i++ {
		x.shiftRight()
	}
	require.Equal(t, "123", x.String())
}

func TestMsb(t *testing.T) {
	x := NewInt(5)
	require.Equal(t, 2, x.Msb())

	x = FromBytes([]byte{0x3d, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	require.Equal(t, 77, x.Msb())
}

func TestFib(t *testing.T) {
	n0 := One
	n1 := One
	for i := 2; i <= 100; i++ {
		t := n0.Add(n1)
		n0 = n1
		n1 = t
	}
	require.Equal(t, "573147844013817084101", n1.String())
}

func TestFact(t *testing.T) {
	n := One
	for i := 2; i <= 30; i++ {
		n = n.Mul(NewInt(int64(i)))
	}
	require.Equal(t, "265252859812191058636308480000000", n.String())
}

func randomPair(size int) (*big.Int, *Int) {
	buf := []byte{}
	for i := rand.Intn(size); i > 0; i-- {
		buf = append(buf, byte(rand.Intn(256)))
	}
	n := &big.Int{}
	n.SetBytes(buf)
	return n, FromBytes(buf)
}

// func interestingPieces() []uint64 {
// 	t := []uint8{
// 		0x00,
// 		0x01,
// 		0x55,
// 		0x7f,
// 		0x80,
// 		0xaa,
// 		0xff,
// 	}
// 	return []uint64{
// 		0x0000000000000000,
// 		0x0000000000000001,

// 		0x00000000000000fe,
// 		0x00000000000000ff,

// 		0x7fffffffffffffff,
// 		0x80ffffffffffffff,
// 		0xaaaaaaaaaaaaaaaa,
// 		0x5555555555555555,
// 	}
// }

// func interestingValues() []*Int {
// 	// Take 1, 2, 3 or 4 interestingPieces and glue them together.

// 	return nil
// }

// // func TestMeh(t *testing.T) {
// // 	buf := utils.HexToByteSlice("fffffffffffffffff000000000000003")
// // 	xx := FromBytes(buf)
// // 	yy := FromBytes(buf)
// // 	rr := xx.Mul(yy)

// // 	x := &big.Int{}
// // 	x.SetBytes(buf)
// // 	r := &big.Int{}
// // 	r.Mul(x, x)
// // 	require.Equal(t, r.String(), rr.String())
// // }

package rng

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	mathrand "math/rand"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type Rng struct {
	seed    int64
	rng     *mathrand.Rand
	printed bool
}

func New() *Rng {
	buf := make([]byte, 8)
	_, err := rand.Read(buf)
	utils.PanicOnErr(err)
	buf[0] = buf[0] & 0x7f
	seed := int64(binary.BigEndian.Uint64(buf))

	r := &Rng{
		seed:    seed,
		printed: false,
	}
	r.rng = mathrand.New(mathrand.NewSource(r.seed))
	return r
}

func (rng *Rng) printSeed() {
	if !rng.printed {
		fmt.Printf("seed: %d\n", rng.seed)
		rng.printed = true
	}
}

func (rng *Rng) Bytes(size int) []byte {
	rng.printSeed()
	r := make([]byte, size)
	_, err := rng.rng.Read(r)
	utils.PanicOnErr(err)
	return r
}

// Returns a random BigInt in the range [1, n-1]
func (rng *Rng) BigInt(n *big.Int) *big.Int {
	rng.printSeed()
	l := n.BitLen() / 8
	if n.BitLen()%8 != 0 {
		l += 1
	}
	for {
		buf := rng.Bytes(l)
		x := &big.Int{}
		x.SetBytes(buf)
		if x.Cmp(n) != -1 {
			continue
		}
		if bigutils.IsZero(x) {
			continue
		}
		return x
	}
}

func (rng *Rng) Int(n int) int {
	rng.printSeed()
	return rng.rng.Intn(n)
}

func (rng *Rng) Int32(n int32) int32 {
	rng.printSeed()
	return rng.rng.Int31n(n)
}

func (rng *Rng) Int64(n int64) int64 {
	rng.printSeed()
	return rng.rng.Int63n(n)
}

func (rng *Rng) Uint64() uint64 {
	rng.printSeed()
	return rng.rng.Uint64()
}

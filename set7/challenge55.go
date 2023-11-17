package set7

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/md4"
)

func Challenge55() {
	utils.PrintTitle(7, 55)

	extraChecks := false
	counter := 0
	msg1 := make([]byte, 64)
	msg2 := make([]byte, 64)
	for {
		counter++
		if counter%100_000 == 0 {
			fmt.Printf(".")
		}
		// Start with a random 512-bit message
		_, err := rand.Read(msg1)
		utils.PanicOnErr(err)

		// Fix the message using table 6 from paper
		_ = fixup(msg1)

		// optional: double check that the fixup worked
		if extraChecks {
			ok := fixup(msg1)
			if !ok {
				panic("fixup failed")
			}
		}

		// Compute MD4 of msg. Tiny optimization: we can drop the padding since
		// both messages are already 512 bits.
		hasher := md4.NewMd4()
		hasher.SkipPadding()
		hasher.Update(msg1)
		hash1 := hasher.Digest()

		// TODO: figure out why these specific values work!
		copy(msg2, msg1)
		x := [16]uint32{}
		for i := 0; i < 16; i++ {
			x[i] = binary.LittleEndian.Uint32(msg2[i*4:])
		}
		x[1] = x[1] + (1 << 31)
		x[2] = x[2] + ((1 << 31) - (1 << 28))
		x[12] = x[12] - (1 << 16)
		for i := 0; i < 16; i++ {
			binary.LittleEndian.PutUint32(msg2[i*4:], x[i])
		}

		hasher = md4.NewMd4()
		hasher.SkipPadding()
		hasher.Update(msg2)
		hash2 := hasher.Digest()
		if slices.Equal(hash1, hash2) {
			fmt.Printf("\nFound a collision!\n")
			fmt.Printf("%s\n", utils.ByteSliceToHex(msg1))
			fmt.Printf("%s\n", utils.ByteSliceToHex(msg2))
			return
		}
	}
}

func fixup(msg []byte) bool {
	if len(msg) != 64 {
		panic("incorrect msg length")
	}

	good := true

	// perform first round of md4. I'm lazy and haven't fully understood how
	// to set things up for the second round. I would need to sit down and
	// carefully grok the math.
	a := uint32(0x67452301)
	b := uint32(0xefcdab89)
	c := uint32(0x98badcfe)
	d := uint32(0x10325476)

	x := [16]uint32{}
	for i := 0; i < 16; i++ {
		x[i] = binary.LittleEndian.Uint32(msg[i*4:])
	}

	fix_ff := func(a, b, c, d uint32, k, s int, checks []uint32) uint32 {
		r := md4.FF(a, b, c, d, x[k], s)
		ok := true
		for i := 0; i < len(checks); i += 2 {
			if utils.GetBit(r, checks[i]) != checks[i+1] {
				ok = false
				r = utils.SetBit(r, checks[i], checks[i+1])
			}
		}
		if !ok {
			x[k] = utils.RotateRight(r, s) - a - md4.F(b, c, d)
			good = false
		}
		return r
	}

	// per table 6
	// note: in the paper, the bits in table 6 are 1-indexed.
	// a1,6 = b0,6
	a = fix_ff(a, b, c, d, 0, 3, []uint32{
		6, utils.GetBit(b, 6),
	})

	// d1,6 = 0
	// d1,7 = a1,7
	// d1,10 = a1,10
	d = fix_ff(d, a, b, c, 1, 7, []uint32{
		6, 0,
		7, utils.GetBit(a, 7),
		10, utils.GetBit(a, 10),
	})

	// c1,6 =1
	// c1,7 =1
	// c1,10 = 0
	// c1,25 = d1,25
	c = fix_ff(c, d, a, b, 2, 11, []uint32{
		6, 1,
		7, 1,
		10, 0,
		25, utils.GetBit(d, 25),
	})

	// b1,6 = 1
	// b1,7 = 0
	// b1,10 = 0
	// b1,25 = 0
	b = fix_ff(b, c, d, a, 3, 19, []uint32{
		6, 1,
		7, 0,
		10, 0,
		25, 0,
	})

	// a2,7 = 1
	// a2,10 = 1
	// a2,25 = 0
	// a2,13 = b1,13
	a = fix_ff(a, b, c, d, 4, 3, []uint32{
		7, 1,
		10, 1,
		25, 0,
		13, utils.GetBit(b, 13),
	})

	// d2,13 = 0
	// d2,18 = a2,18
	// d2,19 = a2,19
	// d2,20 = a2,20
	// d2,21 = a2,21
	// d2,25 = 1
	d = fix_ff(d, a, b, c, 5, 7, []uint32{
		13, 0,
		18, utils.GetBit(a, 18),
		19, utils.GetBit(a, 19),
		20, utils.GetBit(a, 20),
		21, utils.GetBit(a, 21),
		25, 1,
	})

	// c2,12 = d2,12
	// c2,13 = 0
	// c2,14 = d2,14
	// c2,18 = 0
	// c2,19 = 0
	// c2,20 = 1
	// c2,21 = 0
	c = fix_ff(c, d, a, b, 6, 11, []uint32{
		12, utils.GetBit(d, 12),
		13, 0,
		14, utils.GetBit(d, 14),
		18, 0,
		19, 0,
		20, 1,
		21, 0,
	})

	// b2,12 = 1
	// b2,13 = 1
	// b2,14 = 0
	// b2,16 = c2,16
	// b2,18 = 0
	// b2,19 = 0
	// b2,20 = 0
	// b2,21 = 0
	b = fix_ff(b, c, d, a, 7, 19, []uint32{
		12, 1,
		13, 1,
		14, 0,
		16, utils.GetBit(c, 16),
		18, 0,
		19, 0,
		20, 0,
		21, 0,
	})

	// a3,12 = 1
	// a3,13 = 1
	// a3,14 = 1
	// a3,16 = 0
	// a3,18 = 0
	// a3,19 = 0
	// a3,20 = 0
	// a3,22 = b2,22
	// a3,21 = 1
	// a3,25 = b2,25
	a = fix_ff(a, b, c, d, 8, 3, []uint32{
		12, 1,
		13, 1,
		14, 1,
		16, 0,
		18, 0,
		19, 0,
		20, 0,
		22, utils.GetBit(b, 22),
		21, 1,
		25, utils.GetBit(b, 25),
	})

	// d3,12 = 1
	// d3,13 = 1
	// d3,14 = 1
	// d3,16 = 0
	// d3,19 = 0
	// d3,20 = 1
	// d3,21 = 1
	// d3,22 = 0
	// d3,25 = 1
	// d3,29 = a3,29
	d = fix_ff(d, a, b, c, 9, 7, []uint32{
		12, 1,
		13, 1,
		14, 1,
		16, 0,
		19, 0,
		20, 1,
		21, 1,
		22, 0,
		25, 1,
		29, utils.GetBit(a, 29),
	})

	// c3,16 = 1
	// c3,19 = 0
	// c3,20 = 0
	// c3,21 = 0
	// c3,22 = 0
	// c3,25 = 0
	// c3,29 = 1
	// c3,31 = d3,31
	c = fix_ff(c, d, a, b, 10, 11, []uint32{
		16, 1,
		19, 0,
		20, 0,
		21, 0,
		22, 0,
		25, 0,
		29, 1,
		31, utils.GetBit(d, 31),
	})

	// b3,19 = 0
	// b3,20 = 1
	// b3,21 = 1
	// b3,22 = c3,22
	// b3,25 = 1
	// b3,29 = 0
	// b3,31 = 0
	b = fix_ff(b, c, d, a, 11, 19, []uint32{
		19, 0,
		20, 1,
		21, 1,
		22, utils.GetBit(c, 22),
		25, 1,
		29, 0,
		31, 0,
	})

	// a4,22 = 0
	// a4,25 = 0
	// a4,26 = b3,26
	// a4,28 = b3,28
	// a4,29 = 1
	// a4,31 = 0
	a = fix_ff(a, b, c, d, 12, 3, []uint32{
		22, 0,
		25, 0,
		26, utils.GetBit(b, 26),
		28, utils.GetBit(b, 28),
		29, 1,
		31, 0,
	})

	// d4,22 = 0
	// d4,25 = 0
	// d4,26 = 1
	// d4,28 = 1
	// d4,29 = 0
	// d4,31 = 1
	d = fix_ff(d, a, b, c, 13, 7, []uint32{
		22, 0,
		25, 0,
		26, 1,
		28, 1,
		29, 0,
		31, 1,
	})

	// c4,18 = d4,18
	// c4,22 = 1
	// c4,25 = 1
	// c4,26 = 0
	// c4,28 = 0
	// c4,29 =0
	c = fix_ff(c, d, a, b, 14, 11, []uint32{
		18, utils.GetBit(d, 18),
		22, 1,
		25, 1,
		26, 0,
		28, 0,
		29, 0,
	})

	// b4,18 = 0
	// b4,25 = 1
	// b4,26 = 1
	// b4,28 = 1
	// b4,29 = 0
	b = fix_ff(b, c, d, a, 15, 19, []uint32{
		18, 0,
		25, 1,
		26, 1,
		28, 1,
		29, 0,
	})

	// convert uint32[] back to byte[]
	for i := 0; i < 16; i++ {
		binary.LittleEndian.PutUint32(msg[i*4:], x[i])
	}
	return good
}

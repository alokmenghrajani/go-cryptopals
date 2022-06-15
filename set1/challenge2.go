package set1

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge2() {
	utils.PrintTitle(1, 2)
	input1 := "1c0111001f010100061a024b53535009181c"
	input2 := "686974207468652062756c6c277320657965"
	r := FixedXor(input1, input2)
	fmt.Printf("FixedXor(%q, %q) = %q\n", input1, input2, r)
	if r != "746865206b696420646f6e277420706c6179" {
		panic("fail")
	}
	fmt.Println()
}

// XORs two hex-encoded strings. Returns hex-encoded result.
func FixedXor(input1, input2 string) string {
	if len(input1) != len(input2) {
		panic("invalid inputs")
	}
	buf1 := utils.HexToByteSlice(input1)
	buf2 := utils.HexToByteSlice(input2)
	r := utils.Xor(buf1, buf2)
	return utils.ByteSliceToHex(r)
}

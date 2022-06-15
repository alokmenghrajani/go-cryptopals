package set1

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge1() {
	utils.PrintTitle(1, 1)
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	buf := utils.HexToByteSlice(input)
	r := utils.ByteSliceToBase64(buf)
	fmt.Printf("hexToBase64(%q) = %q\n", input, r)
	if r != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		panic("fail")
	}
	fmt.Println()
}

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
	buf1 := hexToByteSlice(input1)
	buf2 := hexToByteSlice(input2)
	r := make([]byte, 0, len(buf1))
	for i := 0; i < len(buf1); i++ {
		r = append(r, buf1[i]^buf2[i])
	}
	return byteSliceToHex(r)
}

// converts []byte to hex-encoded string.
func byteSliceToHex(buf []byte) string {
	r := make([]byte, 0, len(buf)*2)
	for i := 0; i < len(buf); i++ {
		r = append(r, byteToHex(buf[i])...)
	}
	return string(r)
}

// converts a byte to hex-encoded string.
func byteToHex(buf byte) string {
	r := []byte{0, 0}
	r[0] = nibbleToHex((buf >> 4) & 0xf)
	r[1] = nibbleToHex(buf & 0xf)
	return string(r)
}

// converts a nibble (i.e. half a byte) to a hex-character
func nibbleToHex(buf byte) byte {
	if buf < 10 {
		return '0' + buf
	} else if buf < 16 {
		return 'a' + buf - 10
	} else {
		panic("something is wrong")
	}
}

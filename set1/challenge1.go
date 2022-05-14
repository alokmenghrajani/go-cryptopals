package set1

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge1() {
	utils.PrintTitle(1, 1)
	input := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	buf := hexToByteSlice(input)
	r := utils.ByteSliceToBase64(buf)
	fmt.Printf("hexToBase64(%q) = %q\n", input, r)
	if r != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		panic("fail")
	}
	fmt.Println()
}

// converts a hex string to []byte
func hexToByteSlice(s string) []byte {
	// check that input is a multiple of two
	if (len(s) % 2) != 0 {
		panic("invalid hex")
	}

	// allocate space to convert hex to bytes
	buf := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		// convert hex pair to byte
		buf = append(buf, hexToByte(s[i:i+2]))
	}
	return buf
}

// converts two-character hex to a byte
func hexToByte(s string) byte {
	v := hexToNibble(s[0]) * 16
	v += hexToNibble(s[1])
	return v
}

// converts one-character hex to a nibble (i.e. half a byte)
func hexToNibble(s byte) byte {
	if s >= '0' && s <= '9' {
		return s - '0'
	} else if s >= 'a' && s <= 'f' {
		return s - 'a' + 10
	}
	panic("invalid hex")
}

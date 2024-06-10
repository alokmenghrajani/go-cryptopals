package set1

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge3() {
	utils.PrintTitle(1, 3)
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	_, r := crackSingleByteXor(hex.ToByteSlice(input))
	fmt.Printf("CrackSingleByteXor(%q) = %q\n", input, r)
	fmt.Println()
}

// cracks a single-byte XOR cipher
func crackSingleByteXor(buf []byte) (byte, string) {
	bestScore := -1
	bestResult := []byte{}
	bestKey := byte(0)
	// iterate over every possible byte, xor buffer with byte, get liklihood of resulting
	// buffer being valid english and save the best result.
	for b := 0; b < 256; b++ {
		t := singleByteXor(buf, byte(b))
		score := english(t)
		if score > bestScore {
			bestScore = score
			bestResult = t
			bestKey = byte(b)
		}
	}
	return bestKey, string(bestResult)
}

// xors buffer with a single byte
func singleByteXor(buf []byte, key byte) []byte {
	r := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); i++ {
		r = append(r, buf[i]^key)
	}
	return r
}

// evaluates liklihood of buffer being valid english and returns a score. Higher score means
// higher liklihood of being english.
func english(buf []byte) int {
	// You might think that you need to calculate letter frequencies, sort them, and compare
	// the distribution with expected letter frequencies. I implemented a simpler approach:
	// give a point for each letter in the /[a-zA-Z ]/ range. Simple works.
	r := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] >= 'A' && buf[i] <= 'Z' {
			r++
		} else if buf[i] >= 'a' && buf[i] <= 'z' {
			r++
		} else if buf[i] == ' ' {
			r++
		}
	}
	return r
}

package set1

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge8() {
	utils.PrintTitle(1, 8)
	file, err := os.ReadFile("set1/8.txt")
	utils.PanicOnErr(err)
	inputs := strings.Split(string(file), "\n")
	bestScore := -1
	bestInput := ""
	for i := 0; i < len(inputs); i++ {
		score := aesEcb(utils.HexToByteSlice(inputs[i]))
		if score > bestScore {
			bestScore = score
			bestInput = inputs[i]
		}
	}
	fmt.Println(bestInput)
	fmt.Println()
}

// evaluates liklihood of buffer being encrypted with aesEcb and returns a score.
// Higher score means higher liklihood of being aesEcb.
func aesEcb(buf []byte) int {
	// check that we have a multiple of 16 bytes, which is AES' block size.
	if len(buf)%16 != 0 {
		return 0
	}

	// count how many duplicate blocks we find
	score := 1
	for i := 0; i < len(buf); i += 16 {
		for j := i + 16; j < len(buf); j += 16 {
			if bytes.Equal(buf[i:i+16], buf[j:j+16]) {
				score++
			}
		}
	}
	return score
}

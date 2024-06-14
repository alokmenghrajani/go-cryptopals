package set1

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
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
		score := aesEcb(hex.ToByteSlice(inputs[i]))
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
	if len(buf)%aes.BlockSize != 0 {
		panic(fmt.Errorf("buffer isn't a multiple of aes.BlockSize: %d", len(buf)))
	}

	// count how many duplicate blocks we find
	score := 1
	for i := 0; i < len(buf); i += aes.BlockSize {
		for j := i + aes.BlockSize; j < len(buf); j += aes.BlockSize {
			if bytes.Equal(buf[i:i+aes.BlockSize], buf[j:j+aes.BlockSize]) {
				score++
			}
		}
	}
	return score
}

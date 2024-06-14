package set1

import (
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge4() {
	utils.PrintTitle(1, 4)
	file, err := os.ReadFile("set1/4.txt")
	utils.PanicOnErr(err)
	inputs := strings.Split(string(file), "\n")

	// same code as challenge 3, but we are now looking for the best score among
	// all the inputs.
	bestScore := -1
	bestResult := []byte{}
	for i := 0; i < len(inputs); i++ {
		buf := hex.ToByteSlice(inputs[i])
		for b := 0; b < 256; b++ {
			t := singleByteXor(buf, byte(b))
			score := english(t)
			if score > bestScore {
				bestScore = score
				bestResult = t
			}
		}
	}
	fmt.Println(string(bestResult))
	fmt.Println()
}

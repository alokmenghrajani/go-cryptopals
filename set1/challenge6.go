package set1

import (
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge6() {
	utils.PrintTitle(1, 6)
	file, err := os.ReadFile("set1/6.txt")
	if err != nil {
		panic(err)
	}
	input := strings.Join(strings.Split(string(file), "\n"), "")
	buf := utils.Base64ToByteSlice(input)

	// taking a shortcut here by not trying to guess the keysize
	bestScore := -1
	bestOutput := ""
	bestKey := ""
	for keySize := 2; keySize <= 40; keySize++ {
		// crack each byte of the key one by one
		finalKey := []byte{}
		for i := 0; i < keySize; i++ {
			t := buildBuffer(buf, i, keySize)
			key, _ := crackSingleByteXor(t)
			finalKey = append(finalKey, key)
		}
		// apply the repreated XOR and compare english score
		t := utils.HexToByteSlice(encryptRepeatedXor(buf, finalKey))
		v := english(t)
		if v > bestScore {
			// store the best result
			bestScore = v
			bestOutput = string(t)
			bestKey = string(finalKey)
		}
	}
	fmt.Println(bestOutput)
	fmt.Printf("Key: %q\n", bestKey)
	fmt.Println()
}

func buildBuffer(buf []byte, offset, keySize int) []byte {
	r := make([]byte, 0, len(buf)/keySize)
	for i := offset; i < len(buf); i += keySize {
		r = append(r, buf[i])
	}
	return r
}

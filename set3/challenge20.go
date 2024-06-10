package set3

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

// My solution for challenge20 is identical as for challenge19. The ends of the strings
// don't come out right...
func Challenge20() {
	utils.PrintTitle(3, 20)

	ciphertexts := getCiphertextsFromFile()

	// calculate longest ciphertext
	max := 0
	for _, ciphertext := range ciphertexts {
		if len(ciphertext) > max {
			max = len(ciphertext)
		}
	}

	// for each keystream byte, find the value which results in the most ascii values
	// this works fine for the first few bytes, but since the number of ciphertexts drops
	// as the value of i increases, the accuracy of this method decreases.
	// It's however quite easy to fix each sentence by hand.
	keyStream := []byte{}
	for i := 0; i < max; i++ {
		bestScore := -1
		bestValue := byte(0)
		for j := 0; j < 256; j++ {
			score := 0
			for _, ciphertext := range ciphertexts {
				if i >= len(ciphertext) {
					continue
				}
				t := ciphertext[i] ^ byte(j)
				if t >= 'a' && t <= 'z' {
					score++
				} else if t >= 'A' && t <= 'Z' {
					score++
				} else if t == ' ' {
					score++
				}
			}
			if score > bestScore {
				bestScore = score
				bestValue = byte(j)
			}
		}
		keyStream = append(keyStream, bestValue)
	}

	for _, ciphertext := range ciphertexts {
		plaintext := []byte{}
		for i := 0; i < len(ciphertext); i++ {
			plaintext = append(plaintext, ciphertext[i]^keyStream[i])
		}
		fmt.Println(string(plaintext))
	}

	fmt.Println()
}

func getCiphertextsFromFile() [][]byte {
	ciphertexts := [][]byte{}
	file, err := ioutil.ReadFile("set3/20.txt")
	utils.PanicOnErr(err)
	plaintexts := strings.Split(string(file), "\n")

	aesKey := make([]byte, 16)
	_, err = rand.Read(aesKey)
	utils.PanicOnErr(err)
	for _, plaintext := range plaintexts {
		aesCtr := aes.NewAesCtr(aesKey, 0)
		ciphertexts = append(ciphertexts, aesCtr.Process(base64.ToByteSlice(plaintext)))
	}

	return ciphertexts
}

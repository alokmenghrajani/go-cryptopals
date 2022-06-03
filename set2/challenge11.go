package set2

import (
	"bytes"
	"crypto/rand"
	"fmt"
	insecureRand "math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

const (
	CBC = 0
	ECB = 1
)

func Challenge11() {
	utils.PrintTitle(2, 11)

	// Generate a random AES key
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	correct := 0
	total := 1000
	insecureRand.Seed(time.Now().Unix())
	for i := 0; i < total; i++ {
		plaintext := []byte("yellow submarineyellow submarineyellow submarine")
		ciphertext, mode := encryptionOracle(plaintext, aesKey)
		mode2 := guessMode(ciphertext)
		if mode == mode2 {
			correct++
		}
	}

	fmt.Printf("Score: %d/%d\n", correct, total)
	if correct != total {
		panic("failed")
	}
	fmt.Println()
}

func encryptionOracle(data, key []byte) ([]byte, int) {
	// use a RNG to decide number of bytes to prepend, append, and mode.
	prependCount := insecureRand.Intn(6) + 5
	appendCount := insecureRand.Intn(6) + 5
	mode := insecureRand.Intn(2)

	// prepare buffer
	buf := make([]byte, prependCount+appendCount+len(data))
	rand.Read(buf)
	copy(buf[prependCount:prependCount+len(data)], data)
	buf = pad(buf, 16)

	// encrypt the data
	switch mode {
	case CBC:
		iv := make([]byte, 16)
		rand.Read(iv)
		ciphertext := aesCbcEncrypt(buf, key, iv)
		return ciphertext, mode
	case ECB:
		ciphertext := aesEcbEncrypt(buf, key)
		return ciphertext, mode
	}
	panic("unreachable")
}

func aesEcbEncrypt(buf, key []byte) []byte {
	cipher := utils.NewAes(key)
	output := []byte{}
	t := make([]byte, 16)
	for i := 0; i < len(buf); i += 16 {
		cipher.Encrypt(t, buf[i:i+16])
		output = append(output, t...)
	}
	return output
}

func guessMode(buf []byte) int {
	for i := 0; i < len(buf); i += 16 {
		for j := i + 16; j < len(buf); j += 16 {
			if bytes.Equal(buf[i:i+16], buf[j:j+16]) {
				return ECB
			}
		}
	}
	return CBC
}

package set2

import (
	"bytes"
	"crypto/rand"
	"fmt"
	insecureRand "math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
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
	buf = pkcs7.Pad(buf, aes.BlockSize)

	// encrypt the data
	switch mode {
	case CBC:
		iv := make([]byte, aes.BlockSize)
		_, err := rand.Read(iv)
		utils.PanicOnErr(err)
		ciphertext := aes.AesCbcEncrypt(buf, key, iv)
		return ciphertext, mode
	case ECB:
		ciphertext := aesEcbEncrypt(buf, key)
		return ciphertext, mode
	}
	panic("unreachable")
}

func aesEcbEncrypt(buf, key []byte) []byte {
	cipher := aes.NewAes(key)
	output := []byte{}
	t := make([]byte, aes.BlockSize)
	for i := 0; i < len(buf); i += aes.BlockSize {
		cipher.Encrypt(t, buf[i:i+aes.BlockSize])
		output = append(output, t...)
	}
	return output
}

func guessMode(buf []byte) int {
	for i := 0; i < len(buf); i += aes.BlockSize {
		for j := i + aes.BlockSize; j < len(buf); j += aes.BlockSize {
			if bytes.Equal(buf[i:i+aes.BlockSize], buf[j:j+aes.BlockSize]) {
				return ECB
			}
		}
	}
	return CBC
}

package set2

import (
	"bytes"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

const (
	CBC = 0
	ECB = 1
)

func Challenge11(rng *rng.Rng) {
	utils.PrintTitle(2, 11)

	// Generate a random AES key
	aesKey := rng.Bytes(aes.KeySize)

	correct := 0
	total := 1000
	for i := 0; i < total; i++ {
		plaintext := []byte("yellow submarineyellow submarineyellow submarine")
		ciphertext, mode := encryptionOracle(rng, plaintext, aesKey)
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

func encryptionOracle(rng *rng.Rng, data, key []byte) ([]byte, int) {
	// use a RNG to decide number of bytes to prepend, append, and mode.
	prependCount := rng.Int(6) + 5
	appendCount := rng.Int(6) + 5
	mode := rng.Int(2)

	// prepare buffer
	buf := rng.Bytes(prependCount + appendCount + len(data))
	copy(buf[prependCount:prependCount+len(data)], data)
	buf = pkcs7.Pad(buf, aes.BlockSize)

	// encrypt the data
	switch mode {
	case CBC:
		iv := rng.Bytes(aes.BlockSize)
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

package set7

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/rc4"
	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type z16andz32bias struct {
	z16bias byte
	z32bias byte
}

func Challenge56() {
	utils.PrintTitle(7, 56)

	// Track statistics about ciphertext bias at offsets 15 and 31 when encrypting
	// 0x00 0x00... with random keys. The code is slow because of the rc4
	// initialization with random keys.
	fmt.Println("Computing bias")
	z16bias, z32bias := recover(1<<23, make([]byte, 32))
	fmt.Printf("z16 bias: %02x\n", z16bias)
	fmt.Printf("z32 bias: %02x\n", z32bias)

	// Crack the secret
	cookie := base64.ToByteSlice("QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F")
	recovered := make([]byte, len(cookie))
	plaintext := make([]byte, len(cookie)+15)
	for i := 0; i < 16; i++ {
		copy(plaintext[i:], cookie)
		// recover bytes 15-i and 31-i
		b1, b2 := recover(1<<25, plaintext)
		if 15-i < len(recovered) {
			recovered[15-i] = b1 ^ z16bias
		}
		if 31-i < len(recovered) {
			recovered[31-i] = b2 ^ z32bias
		}
		fmt.Printf("cracking: %02x\n", recovered)
	}

	fmt.Printf("Done: %s\n", string(recovered))
	if !bytes.Equal(cookie, recovered) {
		panic("mismatch")
	}

	fmt.Println()
}

func max(m map[byte]int) (byte, int) {
	maxK := byte(0)
	maxV := 0
	for k, v := range m {
		if v > maxV {
			maxK = k
			maxV = v
		}
	}
	return maxK, maxV
}

func recover(rounds int, plaintext []byte) (byte, byte) {
	z16counts := map[byte]int{}
	z32counts := map[byte]int{}
	for i := 0; i < rounds; i++ {
		key := make([]byte, 16)
		_, err := rand.Read(key)
		utils.PanicOnErr(err)
		rc4 := rc4.New(key)
		ciphertext := rc4.Process(plaintext)
		if len(ciphertext) >= 16 {
			z16counts[ciphertext[15]]++
		}
		if len(ciphertext) >= 32 {
			z32counts[ciphertext[31]]++
		}
	}
	z16bias, _ := max(z16counts)
	z32bias, _ := max(z32counts)
	return z16bias, z32bias
}

package set3

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	insecureRand "math/rand"
	"strings"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type MTCipher struct {
	mt           *MT
	currentBytes []byte
}

func NewMTCipher(seed uint16) *MTCipher {
	return &MTCipher{
		mt:           NewMT(uint32(seed)),
		currentBytes: []byte{},
	}
}

func (mtc *MTCipher) process(buf []byte) []byte {
	r := []byte{}
	for _, v := range buf {
		if len(mtc.currentBytes) == 0 {
			mtc.currentBytes = make([]byte, 4)
			binary.BigEndian.PutUint32(mtc.currentBytes, mtc.mt.next())
		}
		r = append(r, v^mtc.currentBytes[0])
		mtc.currentBytes = mtc.currentBytes[1:]
	}
	return r
}

func Challenge24() {
	utils.PrintTitle(3, 24)

	ciphertext := generateCiphertext()

	for seed := 0; seed < 0x10000; seed++ {
		plaintext := NewMTCipher(uint16(seed)).process(ciphertext)
		if bytes.Equal(plaintext[len(plaintext)-4:], []byte("AAAA")) {
			fmt.Printf("possible seed: %d\n", seed)
		}
	}

	fmt.Println()
}

func generateCiphertext() []byte {
	insecureRand.Seed(time.Now().Unix())
	seed := uint16(insecureRand.Int())
	fmt.Printf("seed: %d\n", seed)

	lenPrefix := insecureRand.Intn(20) + 5
	plaintext := make([]byte, lenPrefix)
	_, err := rand.Read(plaintext)
	utils.PanicOnErr(err)

	plaintext = append(plaintext, []byte(strings.Repeat("A", 14))...)
	return NewMTCipher(seed).process(plaintext)
}

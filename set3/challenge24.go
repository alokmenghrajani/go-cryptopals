package set3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/rng"
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

func Challenge24(rng *rng.Rng) {
	utils.PrintTitle(3, 24)

	ciphertext := generateCiphertext(rng)

	for seed := 0; seed < 0x10000; seed++ {
		plaintext := NewMTCipher(uint16(seed)).process(ciphertext)
		if bytes.Equal(plaintext[len(plaintext)-4:], []byte("AAAA")) {
			fmt.Printf("possible seed: %d\n", seed)
		}
	}

	fmt.Println()
}

func generateCiphertext(rng *rng.Rng) []byte {
	seed := uint16(rng.Uint64())
	fmt.Printf("MT seed: %d\n", seed)

	lenPrefix := rng.Int(20) + 5
	plaintext := rng.Bytes(lenPrefix)
	plaintext = append(plaintext, []byte(strings.Repeat("A", 14))...)

	return NewMTCipher(seed).process(plaintext)
}

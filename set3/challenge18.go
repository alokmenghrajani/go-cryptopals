package set3

import (
	"encoding/binary"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type AesCtr struct {
	key       []byte
	nonce     uint64
	nextBlock uint64
	keystream []byte
}

func NewAesCtr(key []byte, nonce uint64) *AesCtr {
	return &AesCtr{
		key:       key,
		nonce:     nonce,
		nextBlock: 0,
		keystream: []byte{},
	}
}

func (aesCtr *AesCtr) xor(v byte) byte {
	if len(aesCtr.keystream) == 0 {
		aes := utils.NewAes(aesCtr.key)
		aesCtr.keystream = make([]byte, 16)
		input := make([]byte, 16)
		binary.LittleEndian.PutUint64(input, aesCtr.nonce)
		binary.LittleEndian.PutUint64(input[8:], aesCtr.nextBlock)
		aes.Encrypt(aesCtr.keystream, input)
		aesCtr.nextBlock++
	}
	r := v ^ aesCtr.keystream[0]
	aesCtr.keystream = aesCtr.keystream[1:]
	return r
}

func (aesCtr *AesCtr) process(input []byte) []byte {
	r := []byte{}
	for _, v := range input {
		r = append(r, aesCtr.xor(v))
	}
	return r
}

func Challenge18() {
	utils.PrintTitle(3, 18)

	aesCtr := NewAesCtr([]byte("YELLOW SUBMARINE"), 0)
	ciphertext := utils.Base64ToByteSlice("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	plaintext := aesCtr.process(ciphertext)
	fmt.Println(string(plaintext))

	fmt.Println()
}

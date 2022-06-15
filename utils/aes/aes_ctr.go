package aes

import "encoding/binary"

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

func (aesCtr *AesCtr) Process(input []byte) []byte {
	r := []byte{}
	for _, v := range input {
		r = append(r, aesCtr.xor(v))
	}
	return r
}

func (aesCtr *AesCtr) xor(v byte) byte {
	if len(aesCtr.keystream) == 0 {
		aes := NewAes(aesCtr.key)
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

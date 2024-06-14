package set7

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type request struct {
	message []byte
	iv      []byte
	mac     []byte
}

func Challenge49() {
	utils.PrintTitle(7, 49)

	fmt.Println("part 1:")
	part1()

	fmt.Println("part 2:")
	part2()

	fmt.Println()
}

// first part (message || IV || MAC)
func part1() {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	utils.PanicOnErr(err)

	message1 := part1Gen(key)
	if !part1ValidateMessage(key, message1) {
		panic("oops")
	}

	message2 := part1Forge(message1)
	if !part1ValidateMessage(key, message2) {
		panic("forged message isn't valid")
	}
	req := part1ParseBuf(message2)
	fmt.Printf("%q\n", req.message)
}

func part1Gen(key []byte) []byte {
	r := request{}
	r.message = []byte("from=1111&to=2222&amount=1000000")

	r.iv = make([]byte, aes.BlockSize)
	_, err := rand.Read(r.iv)
	utils.PanicOnErr(err)

	r.mac = cbcMac(r.message, r.iv, key)
	return r.part1ToBuf()
}

func part1Forge(message1 []byte) []byte {
	// We can mutate the first 16 bytes of the message and adjust the IV to keep the same CBC-MAC.
	req := part1ParseBuf(message1)

	newMessage := []byte("from=7890&to=2222&amount=1000000")
	delta := utils.Xor(newMessage[0:aes.BlockSize], req.message[0:aes.BlockSize])
	req.message = newMessage
	req.iv = utils.Xor(req.iv, delta)
	return req.part1ToBuf()
}

func part1ValidateMessage(key, buf []byte) bool {
	req := part1ParseBuf(buf)
	expectedMac := cbcMac(req.message, req.iv, key)
	return bytes.Equal(expectedMac, req.mac)
}

func part1ParseBuf(buf []byte) *request {
	if len(buf) < 32 {
		return nil
	}

	return &request{
		message: buf[0 : len(buf)-32],
		iv:      buf[len(buf)-32 : len(buf)-16],
		mac:     buf[len(buf)-16:],
	}
}

func (req request) part1ToBuf() []byte {
	r := make([]byte, 0, len(req.message)+32)
	r = append(r, req.message...)
	r = append(r, req.iv...)
	r = append(r, req.mac...)
	return r
}

// second part (message || MAC)
func part2() {
	key := make([]byte, 16)
	_, err := rand.Read(key)
	utils.PanicOnErr(err)

	interceptedMessage := part2Gen(key, []byte("from=7890&tx_list=5555:20"))
	if !part2ValidateMessage(key, interceptedMessage) {
		panic("oops")
	}

	message := part2Forge(key, interceptedMessage)
	if !part2ValidateMessage(key, message) {
		panic("forged message isn't valid")
	}
	req := part2ParseBuf(message)
	fmt.Printf("%q\n", req.message)
}

func part2Gen(key, message []byte) []byte {
	r := request{}
	r.message = message

	r.iv = make([]byte, aes.BlockSize)

	r.mac = cbcMac(r.message, r.iv, key)
	return r.part2ToBuf()
}

func part2Forge(key, interceptedMessage []byte) []byte {
	// we have:
	// 0 xor plaintext => ... ... ... => ... xor padding => mac
	req := part2ParseBuf(interceptedMessage)

	// we can request some garbage (unclear why a server would return the mac for
	// such garbage):
	// 0 xor (mac xor more data) => mac2
	moreData := []byte(";2222:1000000000")
	extraBlock := utils.Xor(moreData, req.mac)
	message := part2Gen(key, extraBlock)
	req2 := part2ParseBuf(message)

	// and then craft:
	// plaintext + padding + more data
	req.message = pkcs7.Pad(req.message, aes.BlockSize)
	req.message = append(req.message, moreData...)
	req.mac = req2.mac

	return req.part2ToBuf()
}

func part2ValidateMessage(key, buf []byte) bool {
	req := part2ParseBuf(buf)
	expectedMac := cbcMac(req.message, req.iv, key)
	return bytes.Equal(expectedMac, req.mac)
}

func part2ParseBuf(buf []byte) *request {
	if len(buf) < 16 {
		return nil
	}

	return &request{
		message: buf[0 : len(buf)-16],
		iv:      make([]byte, aes.BlockSize),
		mac:     buf[len(buf)-16:],
	}
}

func (req request) part2ToBuf() []byte {
	r := make([]byte, 0, len(req.message)+32)
	r = append(r, req.message...)
	r = append(r, req.mac...)
	return r
}

func cbcMac(message, iv, key []byte) []byte {
	// pad the message, but first make a copy so we don't mangle the message
	paddedMessage := make([]byte, len(message), len(message)+aes.BlockSize)
	copy(paddedMessage, message)
	paddedMessage = pkcs7.Pad(paddedMessage, aes.BlockSize)

	// AES-CBC encrypt and return last block
	aesCipher := aes.NewAes(key)

	prev := make([]byte, aes.BlockSize)
	copy(prev, iv)

	for i := 0; i < len(paddedMessage); i += aes.BlockSize {
		plaintext := paddedMessage[i : i+aes.BlockSize]

		// XOR plaintext with prev
		input := make([]byte, 0, aes.BlockSize)
		for i := 0; i < aes.BlockSize; i++ {
			input = append(input, plaintext[i]^prev[i])
		}

		// Encrypt input
		aesCipher.Encrypt(prev, input)
	}

	return prev
}

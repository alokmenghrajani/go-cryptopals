package set4

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha1"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge29(rng *rng.Rng) {
	utils.PrintTitle(4, 29)

	// generate random key
	key := rng.Bytes(aes.KeySize)

	message, mac := generateSha1Mac(key)
	message2, mac2 := crackSha1Mac(message, mac)

	validateSha1Mac([]byte(message2), mac2, key)
	admin := utils.IsAdmin(message2)
	fmt.Printf("admin: %v\n", admin)

	fmt.Println()
}

func generateSha1Mac(key []byte) (string, []byte) {
	message := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	sha1 := sha1.New()
	sha1.Update(key)
	sha1.Update([]byte(message))
	return message, sha1.Digest()
}

func crackSha1Mac(message string, mac []byte) (string, []byte) {
	// Compute original padding
	buf := []byte(message)
	buf = append(buf, 0x80)
	counter := 16 + len(message)
	n := utils.Remaining(counter+1+8, 64)
	buf = append(buf, make([]byte, n)...)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(counter*8))
	buf = append(buf, b...)

	// Rebuild a sha1 with the correct internal state
	// if we didn't know the key size, we would need to iterate over probable sizes.
	h0 := binary.BigEndian.Uint32(mac)
	h1 := binary.BigEndian.Uint32(mac[4:])
	h2 := binary.BigEndian.Uint32(mac[8:])
	h3 := binary.BigEndian.Uint32(mac[12:])
	h4 := binary.BigEndian.Uint32(mac[16:])

	sha1 := sha1.New()
	sha1.Update(make([]byte, 16))
	sha1.Update(buf)
	sha1.SetState(h0, h1, h2, h3, h4)
	sha1.Update([]byte(";admin=true"))
	newMac := sha1.Digest()

	// Return the forged message and new sha1
	buf = append(buf, []byte(";admin=true")...)
	return string(buf), newMac
}

func validateSha1Mac(message, mac, key []byte) {
	sha1 := sha1.New()
	sha1.Update(key)
	sha1.Update(message)
	mac2 := sha1.Digest()
	if !bytes.Equal(mac, mac2) {
		panic("invalid mac")
	}
}

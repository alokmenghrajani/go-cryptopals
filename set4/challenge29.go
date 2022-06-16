package set4

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge29() {
	utils.PrintTitle(4, 29)

	// generate random key
	key := make([]byte, 16)
	_, err := rand.Read(key)
	utils.PanicOnErr(err)

	message, mac := generateSha1Mac(key)
	message2, mac2 := crackSha1Mac(message, mac)

	validateMac([]byte(message2), mac2, key)
	admin := utils.IsAdmin(message2)
	fmt.Printf("admin: %v\n", admin)

	fmt.Println()
}

func generateSha1Mac(key []byte) (string, []byte) {
	message := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	sha1 := utils.NewSha1()
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

	sha1 := utils.NewSha1()
	sha1.Update(make([]byte, 16))
	sha1.Update(buf)
	sha1.SetState(h0, h1, h2, h3, h4)
	sha1.Update([]byte(";admin=true"))
	newMac := sha1.Digest()

	// Return the forged message and new sha1
	buf = append(buf, []byte(";admin=true")...)
	return string(buf), newMac
}

func validateMac(message, mac, key []byte) {
	sha1 := utils.NewSha1()
	sha1.Update(key)
	sha1.Update(message)
	mac2 := sha1.Digest()
	if !bytes.Equal(mac, mac2) {
		panic("invalid mac")
	}
}

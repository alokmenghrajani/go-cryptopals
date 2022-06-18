package set4

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge30() {
	utils.PrintTitle(4, 30)

	// generate random key
	key := make([]byte, 16)
	_, err := rand.Read(key)
	utils.PanicOnErr(err)

	message, mac := generateMd4Mac(key)
	message2, mac2 := crackMd4Mac(message, mac)

	validateMd4Mac([]byte(message2), mac2, key)
	admin := utils.IsAdmin(message2)
	fmt.Printf("admin: %v\n", admin)

	fmt.Println()
}

func generateMd4Mac(key []byte) (string, []byte) {
	message := "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
	md4 := utils.NewMd4()
	md4.Update(key)
	md4.Update([]byte(message))
	return message, md4.Digest()
}

func crackMd4Mac(message string, mac []byte) (string, []byte) {
	// Compute original padding
	buf := []byte(message)
	buf = append(buf, 0x80)
	counter := 16 + len(message)
	n := utils.Remaining(counter+1+8, 64)
	buf = append(buf, make([]byte, n)...)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(counter*8))
	buf = append(buf, b...)

	// Rebuild a md4 with the correct internal state
	// if we didn't know the key size, we would need to iterate over probable sizes.
	aa := binary.LittleEndian.Uint32(mac)
	bb := binary.LittleEndian.Uint32(mac[4:])
	cc := binary.LittleEndian.Uint32(mac[8:])
	dd := binary.LittleEndian.Uint32(mac[12:])

	md4 := utils.NewMd4()
	md4.Update(make([]byte, 16))
	md4.Update(buf)
	md4.SetState(aa, bb, cc, dd)
	md4.Update([]byte(";admin=true"))
	newMac := md4.Digest()

	// Return the forged message and new md4
	buf = append(buf, []byte(";admin=true")...)
	return string(buf), newMac
}

func validateMd4Mac(message, mac, key []byte) {
	md4 := utils.NewMd4()
	md4.Update(key)
	md4.Update(message)
	mac2 := md4.Digest()
	if !bytes.Equal(mac, mac2) {
		panic("invalid mac")
	}
}

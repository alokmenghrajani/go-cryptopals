package set4

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha1"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge28() {
	utils.PrintTitle(4, 28)

	s := keyedMac([]byte("s3cr3t"), []byte("hello world"))
	fmt.Printf("%x\n", s)

	fmt.Println()
}

func keyedMac(key, message []byte) []byte {
	sha1 := sha1.New()
	sha1.Update(key)
	sha1.Update(message)
	return sha1.Digest()
}

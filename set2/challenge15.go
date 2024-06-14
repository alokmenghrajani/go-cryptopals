package set2

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge15() {
	utils.PrintTitle(2, 15)

	s, err := pkcs7.Unpad([]byte("ICE ICE BABY\x04\x04\x04\x04"), aes.BlockSize)
	fmt.Println(err)
	fmt.Println(string(s))
	fmt.Println()

	s, err = pkcs7.Unpad([]byte("ICE ICE BABY\x05\x05\x05\x05"), aes.BlockSize)
	fmt.Println(err)
	fmt.Println(s)
	fmt.Println()

	s, err = pkcs7.Unpad([]byte("ICE ICE BABY\x01\x02\x03\x04"), aes.BlockSize)
	fmt.Println(err)
	fmt.Println(s)
	fmt.Println()

	fmt.Println()
}

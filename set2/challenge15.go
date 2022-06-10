package set2

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge15() {
	utils.PrintTitle(2, 15)

	s, err := unpad([]byte("ICE ICE BABY\x04\x04\x04\x04"), 16)
	fmt.Println(err)
	fmt.Println(string(s))
	fmt.Println()

	s, err = unpad([]byte("ICE ICE BABY\x05\x05\x05\x05"), 16)
	fmt.Println(err)
	fmt.Println(s)
	fmt.Println()

	s, err = unpad([]byte("ICE ICE BABY\x01\x02\x03\x04"), 16)
	fmt.Println(err)
	fmt.Println(s)
	fmt.Println()

	fmt.Println()
}

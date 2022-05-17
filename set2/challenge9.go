package set2

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge9() {
	utils.PrintTitle(2, 9)
	fmt.Printf("%q\n", string(pad([]byte("YELLOW SUBMARINE"), 20)))
	fmt.Println()
}

// pad buffer using pkcs#7
// the padding scheme is documented here:
// https://datatracker.ietf.org/doc/html/rfc2315#section-10.3
func pad(buf []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic("invalid blocksize")
	}
	paddingSize := blockSize - (len(buf) % blockSize)
	for i := 0; i < paddingSize; i++ {
		buf = append(buf, byte(paddingSize))
	}
	return buf
}

// assumes buffer is padded with pkcs#7 and strips the padding
func unpad(buf []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic("invalid blocksize")
	}
	paddingSize := int(buf[len(buf)-1])
	if paddingSize == 0 || paddingSize > blockSize {
		panic("invalid padding")
	}
	return buf[0 : len(buf)-paddingSize]
}

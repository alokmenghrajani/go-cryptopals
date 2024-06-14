package set2

import (
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge10() {
	utils.PrintTitle(2, 10)
	file, err := os.ReadFile("set2/10.txt")
	utils.PanicOnErr(err)
	input := strings.Join(strings.Split(string(file), "\n"), "")
	buf := base64.ToByteSlice(input)
	buf = aes.AesCbcDecrypt(buf, []byte("YELLOW SUBMARINE"), make([]byte, aes.BlockSize))
	buf, err = pkcs7.Unpad(buf, aes.BlockSize)
	utils.PanicOnErr(err)
	fmt.Println(string(buf))
	fmt.Println()
}

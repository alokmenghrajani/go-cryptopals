package set1

import (
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

func Challenge7() {
	utils.PrintTitle(1, 7)
	file, err := os.ReadFile("set1/7.txt")
	utils.PanicOnErr(err)
	input := strings.Join(strings.Split(string(file), "\n"), "")
	buf := base64.ToByteSlice(input)

	cipher := aes.NewAes([]byte("YELLOW SUBMARINE"))
	output := []byte{}
	t := make([]byte, cipher.BlockSize())
	for i := 0; i < len(buf); i += cipher.BlockSize() {
		cipher.Decrypt(t, buf[i:i+cipher.BlockSize()])
		output = append(output, t...)
	}
	fmt.Println(string(output))

	fmt.Println()
}

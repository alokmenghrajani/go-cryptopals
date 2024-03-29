package set2

import (
	"fmt"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

func Challenge10() {
	utils.PrintTitle(2, 10)
	file, err := os.ReadFile("set2/10.txt")
	utils.PanicOnErr(err)
	input := strings.Join(strings.Split(string(file), "\n"), "")
	buf := utils.Base64ToByteSlice(input)
	buf = aes.AesCbcDecrypt(buf, []byte("YELLOW SUBMARINE"), make([]byte, 16))
	buf, err = utils.Unpad(buf, 16)
	utils.PanicOnErr(err)
	fmt.Println(string(buf))
	fmt.Println()
}

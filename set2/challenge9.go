package set2

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge9() {
	utils.PrintTitle(2, 9)
	fmt.Printf("%q\n", string(pkcs7.Pad([]byte("YELLOW SUBMARINE"), 20)))
	fmt.Println()
}

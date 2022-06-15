package set2

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge9() {
	utils.PrintTitle(2, 9)
	fmt.Printf("%q\n", string(utils.Pad([]byte("YELLOW SUBMARINE"), 20)))
	fmt.Println()
}

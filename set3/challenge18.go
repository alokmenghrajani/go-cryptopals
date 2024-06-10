package set3

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

func Challenge18() {
	utils.PrintTitle(3, 18)

	aesCtr := aes.NewAesCtr([]byte("YELLOW SUBMARINE"), 0)
	ciphertext := base64.ToByteSlice("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	plaintext := aesCtr.Process(ciphertext)
	fmt.Println(string(plaintext))

	fmt.Println()
}

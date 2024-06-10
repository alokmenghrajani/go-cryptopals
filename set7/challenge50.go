package set7

import (
	"bytes"
	"fmt"
	"os"

	"github.com/alokmenghrajani/go-cryptopals/encoding/base64"
	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge50() {
	utils.PrintTitle(7, 50)

	// compute first hash
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)
	expectedHash := hex.ToByteSlice("296b8d7cb78a243dda4d0a61d33bbdd1")

	js := []byte("alert('MZA who was that?');\n")
	hash := cbcMac(js, iv, key)
	if !bytes.Equal(expectedHash, hash) {
		panic("unexpected hash")
	}

	// forge different string
	js2 := []byte("alert('Ayo, the Wu is back!');//")
	hash2 := cbcMac(js2, iv, key)

	finalJs := utils.Pad(js2, 16)

	xorBlock := utils.Xor(js[0:16], hash2)
	finalJs = append(finalJs, xorBlock...)
	finalJs = append(finalJs, js[16:]...)
	hash = cbcMac(finalJs, iv, key)
	if !bytes.Equal(expectedHash, hash) {
		panic("unexpected hash")
	}

	encodedJs := []byte("<html><body><script>")
	encodedJs = append(encodedJs, finalJs...)
	encodedJs = append(encodedJs, []byte("</script></body></html>")...)
	fmt.Println(base64.FromByteSlice(encodedJs))

	file, err := os.Create("50.html")
	utils.PanicOnErr(err)
	defer file.Close()
	_, err = file.WriteString(string(encodedJs))
	utils.PanicOnErr(err)

	fmt.Println()
}

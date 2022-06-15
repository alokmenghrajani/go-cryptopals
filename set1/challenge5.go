package set1

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge5() {
	utils.PrintTitle(1, 5)
	input := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"

	r := encryptRepeatedXor([]byte(input), []byte(key))
	fmt.Printf("encryptXor(%q, %q) = %q\n", input, key, r)

	if r != "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" {
		panic("fail")
	}

	fmt.Println()
}

func encryptRepeatedXor(buf, key []byte) string {
	r := make([]byte, 0, len(buf))
	for i := 0; i < len(buf); i++ {
		r = append(r, buf[i]^key[i%len(key)])
	}
	return utils.ByteSliceToHex(r)
}

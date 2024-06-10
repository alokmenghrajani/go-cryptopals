package set6

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/dsa"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge45() {
	utils.PrintTitle(6, 45)

	// part 1: g=0
	// - signing will always panic (because r will always be 0)
	// - verification will always fail, because v is always 0 but
	//   there's a condition 0<r<q, which means r can never equal v.
	// hence not much code for part 1.

	// part 2: g=p+1
	// keygen will always produce y=1
	// signing will always produce r=1, s=...
	// verification will always succeed if r=1
	params := dsa.DefaultParams()
	params.G.Add(params.P, big.NewInt(1))
	pubKey, privKey := dsa.GenerateKeyPair(params)
	fmt.Printf("pubKey=%s\n", pubKey.Y.String())

	signature := privKey.Sign(nil, []byte("hello world"))
	fmt.Printf("signature: r=%s, s=%s\n", signature.R, signature.S)
	ok := pubKey.Verify([]byte("hello world"), signature)
	fmt.Printf("original signature: %v\n", ok)
	ok = pubKey.Verify([]byte("Goodbye, world"), signature)
	fmt.Printf("forged signature: %v\n", ok)

	fmt.Println()
}

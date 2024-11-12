package set6

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/rsa"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs1_5"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// Simply copy-pasta Challenge 47's code. We already had to handle the
// multiple ranges case.
func Challenge48() {
	utils.PrintTitle(6, 48)

	keySize := 768
	keySizeBytes := keySize / 8
	pubKey, privKey := rsa.GenerateKeyPair(keySize)
	fmt.Printf("n: %d\n", pubKey.N)
	fmt.Printf("e: %d\n", pubKey.E)

	shortPlaintext := "kick it, CC"
	shortPlaintextPadded := pkcs1_5.Pad([]byte(shortPlaintext), keySizeBytes)
	ciphertextBytes := pubKey.Encrypt([]byte(shortPlaintextPadded))
	ciphertext := bigutils.FromBytes(ciphertextBytes)
	fmt.Printf("ciphertext: %d\n", ciphertext)

	twoB = big.NewInt(0x02)
	twoB.Lsh(twoB, uint(keySizeBytes-2)*8)

	threeB = big.NewInt(0x03)
	threeB.Lsh(threeB, uint(keySizeBytes-2)*8)
	threeBMinusOne = &big.Int{}
	threeBMinusOne.Sub(threeB, bigutils.One)

	// find s
	s := step2a(pubKey, privKey, keySizeBytes, ciphertext, ceil(pubKey.N, threeB))
	m := intervalAppend([]Interval{}, twoB, threeBMinusOne)
	m = step3(pubKey, s, m)

	for {
		if len(m) == 0 {
			panic("Failed to find a solution.")
		}

		if len(m) == 1 {
			if m[0].size.Cmp(bigutils.One) == 0 {
				fmt.Printf("Found solution after %d calls to oracle.\n", oracleCalled)

				m[0].low.Mod(m[0].low, pubKey.N)
				bytes := append([]byte{0x00}, m[0].low.Bytes()...)
				msg, err := pkcs1_5.Unpad(bytes, keySizeBytes)
				utils.PanicOnErr(err)
				fmt.Printf("%q\n", msg)
				if string(msg) != shortPlaintext {
					panic("Failed to decrypt correct message.")
				}
				break
			}
			s = step2c(pubKey, privKey, keySizeBytes, ciphertext, m[0], s)
		}

		if len(m) > 1 {
			s.Add(s, bigutils.One)
			s = step2a(pubKey, privKey, keySizeBytes, ciphertext, s)
		}

		// compute intervals
		m = step3(pubKey, s, m)
	}
	fmt.Println()
}

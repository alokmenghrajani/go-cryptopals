package set6

import (
	"bytes"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
	"github.com/alokmenghrajani/go-cryptopals/utils/rsa"
)

func Challenge42() {
	utils.PrintTitle(6, 42)

	// I ran these commands with openssl:
	// openssl genrsa -3 -out myprivate.pem 1024
	// echo -ne "hi mom" > myfile.txt
	// openssl dgst -hex -sha1 -sign myprivate.pem myfile.txt
	// openssl rsa -text -in myprivate.pem

	// load the key and signature
	signature := utils.HexToByteSlice("420d9e40b0c881520ec8aa5e20338b14e46d2daca185863f6bb27ec3f83aa0d7e3b9352ee6972483911be4592bd403f5b671f84a9ff84e879a45ba56afec8bfe1164cdbf411160c1d34bc31cdf4cdd9700f2e11ca469ab2fa20207170989611af9ec066a68d974986e3a51452ade9a94a9b598f6c84b6d42777cf112a9fb73b8")

	pubKey := rsa.PubKey{
		E: big.NewInt(3),
		N: &big.Int{},
	}
	pubKey.N = big.FromBytes(utils.HexToByteSlice("00d3a75c230ccb7b69f8f10d478588309d96bdef1b7042db4a587a4fd1dca880726d5674adb5ace47782ff0e8fdf73be141997a0f69ac598d873179e3e70d728831e4f7a4af9de4635422abc2943b14dafc5fd037e65c573937989c2d763ca08982d0fabf103f0c59045d3dc1d5cb3e994096fe7cb1607f9e3efbe71c71afbfe69"))

	// verify signature
	fmt.Printf("original signature: %v\n", verify(pubKey, signature))

	// force a different signature
	signature2 := forge(pubKey)

	// verify that new signature is valid
	fmt.Printf("forged signature: %v\n", verify(pubKey, signature2))

	// verify that the two signatures are different
	if bytes.Equal(signature, signature2) {
		panic("signatures don't differ")
	}

	fmt.Println()
}

func verify(pubKey rsa.PubKey, signature []byte) bool {
	data := pubKey.Verify(signature)

	offset := 0
	expect := func(seq []byte) bool {
		for i := 0; i < len(seq); i++ {
			if offset == len(data) {
				return false
			}
			if data[offset] != seq[i] {
				return false
			}
			offset++
		}
		return true
	}
	// message should be of the form:
	// 0x00, 0x01, 0xff..., 0x00, 0x3021300906052b0e03021a05000414, hash...

	// check first byte. 0x00 gets dropped because of big.Int.
	if !expect([]byte{0x01}) {
		return false
	}

	// eat all the 0xff
	for data[offset] == 0xff {
		offset++
		if offset == len(data) {
			return false
		}
	}

	// ASN.1 GOOP comes from https://datatracker.ietf.org/doc/html/rfc3447#section-9.2
	if !expect([]byte{0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14}) {
		return false
	}

	// Hash
	sha1 := utils.NewSha1()
	sha1.Update([]byte("hi mom"))
	if !expect(sha1.Digest()) {
		return false
	}

	// Don't check that we are done since the attack requires garbage leftover.
	// if offset != len(data) {
	// 	return false
	// }

	return true
}

func forge(pubKey rsa.PubKey) []byte {
	forged := []byte{0x01, 0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
		0x92, 0x5a, 0x89, 0xb4, 0x3f, 0x3c, 0xaf, 0xf5, 0x07, 0xdb, 0x0a, 0x86, 0xd2, 0x0a, 0x24, 0x28, 0x00, 0x7f, 0x10, 0xb6}
	goal := len(forged)

	for i := 0; i < 200; i++ {
		// keep adding garbage until ^3 returns the original data
		forged = append(forged, 0x01)
		n := big.FromBytes(forged)

		r := n.Root(3)
		t := r.ExpMod(big.NewInt(3), pubKey.N)
		buf := t.Bytes()
		if bytes.Equal(buf[0:goal], forged[0:goal]) {
			return r.Bytes()
		}
	}
	panic("failed")
}

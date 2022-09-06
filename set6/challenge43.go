package set6

import (
	"bytes"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
	"github.com/alokmenghrajani/go-cryptopals/utils/dsa"
)

func Challenge43() {
	utils.PrintTitle(6, 43)

	// Recover x by using a known k
	pubKey, privKey := dsa.GenerateKeyPair()
	msg := []byte("hello world")
	signature := privKey.Sign(msg)

	sha1 := utils.NewSha1()
	sha1.Update(msg)
	x := recoverX(pubKey, sha1.Digest(), signature, privKey.K)
	fmt.Printf("x: %d\n", x.Cmp(privKey.X))

	// Bruteforce private key
	pubKey.Y = big.FromBytes(utils.HexToByteSlice("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17"))

	msg = []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")
	signature = dsa.Signature{
		R: &big.Int{},
		S: &big.Int{},
	}
	signature.R = big.FromBytes(utils.HexToByteSlice("60019cacdc56eedf8e080984bfa898c8c5c419a8"))
	signature.S = big.FromBytes(utils.HexToByteSlice("961f2062efc3c68db965a90c924cf76580ec1bbc"))

	privKey = recoverPrivKey(pubKey, msg, signature)
	fmt.Printf("x: %s\n", privKey.X.String())

	fmt.Println()
}

func recoverX(pubKey dsa.PubKey, h []byte, signature dsa.Signature, k *big.Int) *big.Int {
	x := signature.S.Mul(k)

	hh := big.FromBytes(h)

	x = x.Sub(hh)

	t := signature.R.ModInverse(pubKey.Q)
	x = x.Mul(t)
	x = x.Mod(pubKey.Q)

	return x
}

func recoverPrivKey(pubKey dsa.PubKey, msg []byte, signature dsa.Signature) dsa.PrivKey {
	sha1 := utils.NewSha1()
	sha1.Update(msg)
	h := sha1.Digest()
	fmt.Printf("sha1(msg): %02x\n", h)
	if !bytes.Equal(h, []byte{0xd2, 0xd0, 0x71, 0x4f, 0x01, 0x4a, 0x97, 0x84, 0x04, 0x7e, 0xae, 0xcc, 0xf9, 0x56, 0x52, 0x00, 0x45, 0xc4, 0x52, 0x65}) {
		panic("incorrect msg")
	}

	for k := 0; k <= 65536; k++ {
		kk := big.NewInt(int64(k))
		potentialX := recoverX(pubKey, h, signature, kk)
		privKey := dsa.PrivKey{
			P: pubKey.P,
			Q: pubKey.Q,
			G: pubKey.G,
			X: potentialX,
			K: kk,
		}
		sha1 = utils.NewSha1()
		sha1.Update([]byte(fmt.Sprintf("%02x", potentialX.Bytes())))
		d := sha1.Digest()
		if bytes.Equal(d, []byte{0x09, 0x54, 0xed, 0xd5, 0xe0, 0xaf, 0xe5, 0x54, 0x2a, 0x4a, 0xdf, 0x01, 0x26, 0x11, 0xa9, 0x19, 0x12, 0xa3, 0xec, 0x16}) {
			fmt.Println("We found the correct key!")
		}
		signature2 := privKey.Sign(msg)
		if signature2.R.Cmp(signature.R) == 0 && signature2.S.Cmp(signature.S) == 0 {
			return privKey
		}
	}
	panic("meh")
}

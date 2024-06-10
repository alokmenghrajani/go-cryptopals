package set6

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/dsa"
)

func Challenge43() {
	utils.PrintTitle(6, 43)

	// part 1: recover x by using a known k
	pubKey, privKey := dsa.GenerateKeyPair(dsa.DefaultParams())
	msg := []byte("hello world")
	signature := privKey.Sign(nil, msg)
	if signature == nil {
		panic("unexpected")
	}

	sha1 := utils.NewSha1()
	sha1.Update(msg)
	x := recoverX(pubKey, sha1.Digest(), signature)
	if x == nil {
		panic("unexpected")
	}
	fmt.Printf("original key:  %s\n", privKey.X.String())
	fmt.Printf("recovered key: %s\n", x.String())
	if x.Cmp(privKey.X) != 0 {
		panic("mismatch")
	}
	fmt.Println()

	// part 2: find private key by bruteforcing k
	pubKey.Y.SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)

	msg = []byte("For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n")
	signature = &dsa.Signature{
		K: nil,
		R: &big.Int{},
		S: &big.Int{},
	}
	signature.R.SetString("548099063082341131477253921760299949438196259240", 10)
	signature.S.SetString("857042759984254168557880549501802188789837994940", 10)

	privKey = bruteforceK(pubKey, msg, signature)
	fmt.Printf("recovered key: %s\n", privKey.X.String())

	sha1 = utils.NewSha1()
	sha1.Update([]byte(hex.FromByteSlice(privKey.X.Bytes())))
	d := sha1.Digest()
	fmt.Printf("hex: %02x\n", d)

	if !bytes.Equal(d, []byte{0x09, 0x54, 0xed, 0xd5, 0xe0, 0xaf, 0xe5, 0x54, 0x2a, 0x4a, 0xdf, 0x01, 0x26, 0x11, 0xa9, 0x19, 0x12, 0xa3, 0xec, 0x16}) {
		panic("failed to find correct key!")
	}

	fmt.Println()
}

func recoverX(pubKey dsa.PubKey, h []byte, signature *dsa.Signature) *big.Int {
	if signature.K == nil {
		panic("signature.K not set")
	}
	x := &big.Int{}
	x.Mul(signature.S, signature.K)

	hh := &big.Int{}
	hh.SetBytes(h)

	x.Sub(x, hh)

	t := &big.Int{}
	t = t.ModInverse(signature.R, pubKey.Params.Q)
	if t == nil {
		return nil
	}
	x.Mul(x, t)
	x.Mod(x, pubKey.Params.Q)

	return x
}

func bruteforceK(pubKey dsa.PubKey, msg []byte, signature *dsa.Signature) dsa.PrivKey {
	sha1 := utils.NewSha1()
	sha1.Update(msg)
	h := sha1.Digest()
	fmt.Printf("sha1(msg): %02x\n", h)
	if !bytes.Equal(h, []byte{0xd2, 0xd0, 0x71, 0x4f, 0x01, 0x4a, 0x97, 0x84, 0x04, 0x7e, 0xae, 0xcc, 0xf9, 0x56, 0x52, 0x00, 0x45, 0xc4, 0x52, 0x65}) {
		panic("incorrect msg")
	}

	for k := 0; k <= 65536; k++ {
		kk := big.NewInt(int64(k))
		signature.K = kk
		potentialX := recoverX(pubKey, h, signature)
		privKey := dsa.PrivKey{
			Params: pubKey.Params,
			X:      potentialX,
		}
		if checkKey(privKey, signature, msg) {
			return privKey
		}
	}
	panic("meh")
}

func checkKey(privKey dsa.PrivKey, signature *dsa.Signature, msg []byte) bool {
	if signature.K == nil {
		panic("signature.K is nil")
	}
	signature2 := privKey.Sign(signature.K, msg)
	if signature2 == nil {
		return false
	}
	return (signature2.R.Cmp(signature.R) == 0) && (signature2.S.Cmp(signature.S) == 0)
}

package set6

import (
	"bytes"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/dsa"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha1"
	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type data struct {
	id        int
	msg       []byte
	signature dsa.Signature
	m         *big.Int
}

func Challenge44(rng *rng.Rng) {
	utils.PrintTitle(6, 44)

	// Read the file
	file, err := os.ReadFile("set6/44.txt")
	utils.PanicOnErr(err)
	inputs := strings.Split(string(file), "\n")
	datas := []data{}
	for i := 0; i < len(inputs); i += 4 {
		d := data{
			id: i / 4,
			signature: dsa.Signature{
				R: &big.Int{},
				S: &big.Int{},
			},
			m: &big.Int{},
		}
		d.msg = []byte(strings.SplitN(inputs[i], ": ", 2)[1])
		t := strings.SplitN(inputs[i+1], ": ", 2)[1]
		d.signature.S = bigutils.SetString(t, 10)
		t = strings.SplitN(inputs[i+2], ": ", 2)[1]
		d.signature.R = bigutils.SetString(t, 10)
		t = strings.SplitN(inputs[i+3], ": ", 2)[1]
		d.m = bigutils.SetString(t, 16)

		// verify that d.m=H(msg)
		sha1 := sha1.New()
		sha1.Update(d.msg)
		hex := bigutils.FromBytes(sha1.Digest())
		if hex.Cmp(d.m) != 0 {
			panic("meh")
		}

		datas = append(datas, d)
	}

	// create pubkey
	pubKey, _ := dsa.GenerateKeyPair(rng, dsa.DefaultParams())
	pubKey.Y = bigutils.SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)

	// Find which pairs re-used the same k
	var privKey *dsa.PrivKey
	for i := 0; (privKey == nil) && (i < len(datas)); i++ {
		for j := i + 1; (privKey == nil) && (j < len(datas)); j++ {
			privKey = checkPair(rng, pubKey, datas[i], datas[j])
		}
	}
	if privKey == nil {
		panic("failed to find privKey")
	}

	fmt.Printf("recovered key: %s\n", privKey.X.String())
	sha1 := sha1.New()
	sha1.Update([]byte(hex.FromByteSlice(privKey.X.Bytes())))
	d := sha1.Digest()
	fmt.Printf("hex: %02x\n", d)

	if !bytes.Equal(d, []byte{0xca, 0x8f, 0x6f, 0x7c, 0x66, 0xfa, 0x36, 0x2d, 0x40, 0x76, 0x0d, 0x13, 0x5b, 0x76, 0x3e, 0xb8, 0x52, 0x7d, 0x3d, 0x52}) {
		panic("failed to find correct key!")
	}

	fmt.Println()
}

func checkPair(rng *rng.Rng, pubKey dsa.PubKey, left data, right data) *dsa.PrivKey {
	// compute k
	d := &big.Int{}
	d.Sub(left.signature.S, right.signature.S)
	d.Mod(d, pubKey.Params.Q)

	d = d.ModInverse(d, pubKey.Params.Q)
	if d == nil {
		return nil
	}

	k := &big.Int{}
	k.Sub(left.m, right.m)
	k.Mod(k, pubKey.Params.Q)
	k.Mul(k, d)
	k.Mod(k, pubKey.Params.Q)

	// check if k works
	left.signature.K = k
	return recoverFromData(rng, pubKey, left)
}

func recoverFromData(rng *rng.Rng, pubKey dsa.PubKey, d data) *dsa.PrivKey {
	if d.signature.K == nil {
		panic("signature.K not set")
	}

	x := &big.Int{}
	x.Mul(d.signature.S, d.signature.K)

	x.Sub(x, d.m)

	t := &big.Int{}
	t = t.ModInverse(d.signature.R, pubKey.Params.Q)
	if t == nil {
		return nil
	}
	x.Mul(x, t)
	x.Mod(x, pubKey.Params.Q)

	privKey := &dsa.PrivKey{
		Params: pubKey.Params,
		X:      x,
	}
	if checkKey(rng, *privKey, &d.signature, d.msg) {
		return privKey
	}
	return nil
}

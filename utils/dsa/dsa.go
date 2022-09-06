package dsa

import (
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/big"
)

type PubKey struct {
	P *big.Int
	Q *big.Int
	G *big.Int
	Y *big.Int
}

type PrivKey struct {
	P *big.Int
	Q *big.Int
	G *big.Int
	X *big.Int
	K *big.Int
}

type Signature struct {
	R *big.Int
	S *big.Int
}

func GenerateKeyPair() (PubKey, PrivKey) {
	// Set DSA parameters
	p := big.FromBytes(utils.HexToByteSlice("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1"))

	q := big.FromBytes(utils.HexToByteSlice("f4f47f05794b256174bba6e9b396a7707e563c5b"))

	g := big.FromBytes(utils.HexToByteSlice("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291"))

	// pick x randomly from 1..(q-1)
	x := big.Randn(q)
	privKey := &PrivKey{
		P: p,
		Q: q,
		G: g,
		X: x,
		K: nil,
	}

	// y = g^x mod p
	pubKey := &PubKey{
		P: p,
		Q: q,
		G: g,
		Y: &big.Int{},
	}
	pubKey.Y = g.ExpMod(privKey.X, p)

	return *pubKey, *privKey
}

func (privKey *PrivKey) Sign(message []byte) Signature {
	// pick k randomly from 1..(q-1)
	if privKey.K == nil {
		privKey.K = big.Randn(privKey.Q)
	}
	r := privKey.G.ExpMod(privKey.K, privKey.P)
	r = r.Mod(privKey.Q)
	if r.Cmp(big.Zero) == 0 {
		panic("todo: start over with different k")
	}

	sha1 := utils.NewSha1()
	sha1.Update(message)
	h := sha1.Digest()

	hh := big.FromBytes(h)

	s := r.Mul(privKey.X)
	hh = hh.Add(s)

	t := privKey.K.ModInverse(privKey.Q)
	s = t.Mul(hh)
	s = s.Mod(privKey.Q)

	return Signature{
		R: r,
		S: s,
	}
}

func (pubKey *PubKey) Verify(message []byte, signature Signature) bool {
	// check 0<r<q
	if signature.R.Cmp(big.NewInt(0)) != 1 {
		return false
	}
	if signature.R.Cmp(pubKey.Q) != -1 {
		return false
	}

	// check 0<s<q
	if signature.S.Cmp(big.NewInt(0)) != 1 {
		return false
	}
	if signature.S.Cmp(pubKey.Q) != -1 {
		return false
	}

	// compute w
	w := signature.S.ModInverse(pubKey.Q)

	// compute hash
	sha1 := utils.NewSha1()
	sha1.Update(message)
	h := sha1.Digest()

	hh := big.FromBytes(h)

	// compute u1
	u1 := hh.Mul(w)
	u1 = u1.Mod(pubKey.Q)

	// compute u2
	u2 := signature.R.Mul(w)
	u2 = u2.Mod(pubKey.Q)

	// compute v
	v1 := pubKey.G.ExpMod(u1, pubKey.P)

	v2 := pubKey.Y.ExpMod(u2, pubKey.P)

	v := v1.Mul(v2)
	v = v.Mod(pubKey.P)
	v = v.Mod(pubKey.Q)

	// check if v == r
	return v.Cmp(signature.R) == 0
}

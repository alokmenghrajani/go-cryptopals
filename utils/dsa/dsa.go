package dsa

import (
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type PubKey struct {
	p *big.Int
	q *big.Int
	g *big.Int
	y *big.Int
}

type PrivKey struct {
	p *big.Int
	q *big.Int
	g *big.Int
	x *big.Int
}

type Signature struct {
	r *big.Int
	s *big.Int
}

func GenerateKeyPair() (PubKey, PrivKey) {
	// Set DSA parameters
	p := &big.Int{}
	p.SetString("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", 16)

	q := &big.Int{}
	q.SetString("f4f47f05794b256174bba6e9b396a7707e563c5b", 16)

	g := &big.Int{}
	g.SetString("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", 16)

	// pick x randomly from 1..(q-1)
	x := utils.Randn(q)
	privKey := &PrivKey{
		p: p,
		q: q,
		g: g,
		x: x,
	}

	// y = g^x mod p
	pubKey := &PubKey{
		p: p,
		q: q,
		g: g,
		y: &big.Int{},
	}
	pubKey.y.Exp(g, privKey.x, p)

	return *pubKey, *privKey
}

func (privKey *PrivKey) Sign(message []byte) Signature {
	// pick k randomly from 1..(q-1)
	k := utils.Randn(privKey.q)
	r := &big.Int{}
	r.Exp(privKey.g, k, privKey.p)
	r.Mod(r, privKey.q)
	if r.Cmp(big.NewInt(0)) == 0 {
		panic("todo: start over with different k")
	}

	sha1 := utils.NewSha1()
	sha1.Update(message)
	h := sha1.Digest()

	hh := &big.Int{}
	hh.SetBytes(h)

	s := &big.Int{}
	s.Mul(r, privKey.x)
	hh.Add(hh, s)

	t := &big.Int{}
	t.ModInverse(k, privKey.q)
	s.Mul(t, hh)
	s.Mod(s, privKey.q)

	return Signature{
		r: r,
		s: s,
	}
}

func (pubKey *PubKey) Verify(message []byte, signature Signature) bool {
	// check 0<r<q
	if signature.r.Cmp(big.NewInt(0)) != 1 {
		return false
	}
	if signature.r.Cmp(pubKey.q) != -1 {
		return false
	}

	// check 0<s<q
	if signature.s.Cmp(big.NewInt(0)) != 1 {
		return false
	}
	if signature.s.Cmp(pubKey.q) != -1 {
		return false
	}

	// compute w
	w := &big.Int{}
	w.ModInverse(signature.s, pubKey.q)

	// compute hash
	sha1 := utils.NewSha1()
	sha1.Update(message)
	h := sha1.Digest()

	hh := &big.Int{}
	hh.SetBytes(h)

	// compute u1
	u1 := &big.Int{}
	u1.Mul(hh, w)
	u1.Mod(u1, pubKey.q)

	// compute u2
	u2 := &big.Int{}
	u2.Mul(signature.r, w)
	u2.Mod(u2, pubKey.q)

	// compute v
	v1 := &big.Int{}
	v1.Exp(pubKey.g, u1, pubKey.p)

	v2 := &big.Int{}
	v2.Exp(pubKey.y, u2, pubKey.p)

	v := &big.Int{}
	v.Mul(v1, v2)
	v.Mod(v, pubKey.p)
	v.Mod(v, pubKey.q)

	// check if v == r
	return v.Cmp(signature.r) == 0
}

package set8

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/hmacSha256"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge57() {
	utils.PrintTitle(8, 57)

	p := &big.Int{}
	p.SetString("7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771", 10)

	g := &big.Int{}
	g.SetString("4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143", 10)

	q := &big.Int{}
	q.SetString("236234353446506858198510045061214171961", 10)

	// verify that g^q = 1 mod p
	t := &big.Int{}
	t.Exp(g, q, p)
	one := big.NewInt(1)

	if t.Cmp(one) != 0 {
		panic("g^q != 1 mod p")
	}

	// verify that q divides p-1
	pMinusOne := &big.Int{}
	pMinusOne.Sub(p, one)
	t.Mod(pMinusOne, q)
	if !utils.IsZero(t) {
		panic("q does not divide p-1")
	}
	fmt.Println()

	// generate Alice's keys
	alicePriv := utils.Randn(q)
	alicePub := &big.Int{}
	alicePub.Exp(g, alicePriv, p)

	// generate Bob's keys
	bobPriv := utils.Randn(q)
	bobPub := &big.Int{}
	bobPub.Exp(g, bobPriv, p)

	// verify they can exchange a secret
	s1 := &big.Int{}
	s1.Exp(bobPub, alicePriv, p)
	s2 := &big.Int{}
	s2.Exp(alicePub, bobPriv, p)
	if s1.Cmp(s2) != 0 {
		panic("DH failure")
	}

	// j's factors
	f1 := &big.Int{}
	f1.SetString("534232641372537546151", 10)
	f2 := &big.Int{}
	f2.SetString("80913087354323463709999234471", 10)
	factors := []*big.Int{
		big.NewInt(2),
		// we skip 3^2
		big.NewInt(5),
		big.NewInt(109),
		big.NewInt(7963),
		big.NewInt(8539),
		big.NewInt(20641),
		big.NewInt(38833),
		big.NewInt(39341),
		big.NewInt(46337),
		big.NewInt(51977),
		big.NewInt(54319),
		big.NewInt(57529),
		big.NewInt(96142199),
		big.NewInt(46323892554437),
		f1,
		f2,
		q,
	}
	t = big.NewInt(9) // because we dropped 3^2
	for i := 0; i < len(factors); i++ {
		t.Mul(t, factors[i])
	}
	if t.Cmp(pMinusOne) != 0 {
		panic("incorrect factors")
	}

	a := []*big.Int{}
	n := []*big.Int{}

	// iterate over the first 11 elements, because:
	// 2 * 5 * 109 * 7963 * 8539 * 20641 * 38833 * 39341 * 46337 * 51977 * 54319
	// is greater than q.
	for i := 0; i < 11; i++ {
		r := factors[i]
		q2 := &big.Int{}
		q2.Div(pMinusOne, r)
		var h *big.Int
		for {
			h = utils.Randn(p)
			h.Exp(h, q2, p)
			if h.Cmp(one) == 1 {
				break
			}
		}
		msg, t := dh(h, bobPriv, p)
		xModR := findXModR(msg, t, h, p, r)
		a = append(a, xModR)
		n = append(n, r)
	}

	solution, err := utils.Crt(a, n)
	utils.PanicOnErr(err)

	fmt.Printf("bob's key: %d\n", bobPriv)
	fmt.Printf("solution:  %d\n", solution)

	if solution.Cmp(bobPriv) != 0 {
		panic("failed to find Bob's key")
	}

	fmt.Println()
}

func dh(evePublic, bobPriv, p *big.Int) (string, []byte) {
	key := &big.Int{}
	key.Exp(evePublic, bobPriv, p)

	if key.Cmp(big.NewInt(1)) == 0 {
		fmt.Printf("weird: key=1 when public=%d\n", evePublic)
	}

	// note: you shouldn't directly use the output of DH as a key...
	m := "crazy flamboyant for the rap enjoyment"
	t := hmacSha256.Compute(key.Bytes(), []byte(m))
	return m, t
}

func findXModR(msg string, t []byte, h, p, r *big.Int) *big.Int {
	one := big.NewInt(1)
	i := big.NewInt(0)
	for i.Cmp(r) != 1 {
		maybeK := &big.Int{}
		maybeK.Exp(h, i, p)
		t2 := hmacSha256.Compute(maybeK.Bytes(), []byte(msg))
		if bytes.Equal(t, t2) {
			return i
		}
		i.Add(i, one)
	}
	panic("failed to find k")
}

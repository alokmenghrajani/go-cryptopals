package big

// ExtendedGCD returns a tuple (x, y, z) such that v1 * x + v2 * y = z.
// To keep things simple, v1 and v2 have to be > 0.
// Algorithm description:
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
func (v1 *Int) ExtendedGCD(v2 *Int) (*Int, *Int, *Int) {
	if v1.neg || v1.IsZero() {
		panic("v1 is neg or zero")
	}
	if v2.neg || v2.IsZero() {
		panic("v2 is neg or zero")
	}
	oldR := v1
	oldS := One
	oldT := Zero

	r := v2
	s := Zero
	t := One

	for !r.IsZero() {
		q, nextR := oldR.Div(r)
		nextS := oldS.Sub(s.Mul(q))
		nextT := oldT.Sub(t.Mul(q))

		//		fmt.Printf("here: %s, %s, %s, %s\n", q.String(), nextR.String(), nextS.String(), nextT.String())

		oldR, oldS, oldT = r, s, t
		r, s, t = nextR, nextS, nextT
	}
	return oldR, oldS, oldT
}

// ModInverse returns the multiplicative inverse of v1 in the ring ℤ/v2ℤ.
// If v1 and v2 are not relatively prime, v1 has no multiplicative
// inverse in the ring ℤ/v2ℤ.  In this case, the return value is nil.
func (v1 *Int) ModInverse(v2 *Int) *Int {
	r, x, _ := v1.ExtendedGCD(v2)
	if r.Cmp(One) != 0 {
		// v1 and v2 aren't co-prime
		return nil
	}
	if x.neg {
		return x.Add(v2)
	}
	return x
}

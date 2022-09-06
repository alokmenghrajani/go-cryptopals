package big

// ExpMod performs modular exponentiation using square and multiply.
// If m == 0, a division-by-zero run-time panic occurs.
// TODO: implement case when v2 is negative.
func (v1 *Int) ExpMod(v2 *Int, m *Int) *Int {
	r := One

	if v2.IsZero() {
		return r.Mod(m)
	}
	if v2.neg {
		panic("unimplemented")
	}

	t1 := v1.clone()
	t2 := v2.clone()

	for !t2.IsZero() {
		if t2.v[0]&1 == 1 {
			r = r.Mul(t1)
			r = r.Mod(m)
			//			t2.v[0] = t2.v[0] & 0xfffffffffffffffe
			t2.v[0] = t2.v[0] & ((M << 1) & M)
		} else {
			t1 = t1.Mul(t1)
			t1 = t1.Mod(m)
			t2.shiftRight()
		}
	}
	return r
}

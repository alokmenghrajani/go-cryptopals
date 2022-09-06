package big

// Mul returns the product v1*v2. Uses peasant multiplication method which is easier
// to implement but is not optimal.
func (v1 *Int) Mul(v2 *Int) *Int {
	t := v1.absMul(v2)
	if (v1.neg && !v2.neg) || (!v1.neg && v2.neg) {
		// Maybe Go will one day define xor (^) on bools...
		t.neg = true
	}
	t.normalize()
	return t
}

func (v1 *Int) absMul(v2 *Int) *Int {
	n1 := v1.clone()
	n2 := v2.clone()
	if n1.Msb() > n2.Msb() {
		// micro-optimization: iterate over the smaller of the two numbers
		// note: it's probably better to iterate over the number with the least bits set
		n1, n2 = n2, n1
	}
	r := NewInt(0)
	for !n1.IsZero() {
		if (n1.at(0) & 1) == 1 {
			r = n2.absAdd(r)
		}
		n1.shiftRight()
		n2.shiftLeft()
	}
	return r
}

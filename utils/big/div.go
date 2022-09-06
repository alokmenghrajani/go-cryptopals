package big

// Div performs division of v1 by v2 using shift and subtract. The function returns
// the quotient and remainder.
// If v2 == 0, a division-by-zero run-time panic occurs.
func (v1 *Int) Div(v2 *Int) (*Int, *Int) {
	t, r := v1.absDiv(v2)
	if (v1.neg && !v2.neg) || (!v1.neg && v2.neg) {
		// Maybe Go will one day define xor (^) on bools...
		t.neg = true
	}
	if v1.neg && !r.IsZero() {
		r.neg = true
		if v2.neg {
			t = t.Add(One)
			r = r.Sub(v2)
		} else {
			t = t.Sub(One)
			r = r.Add(v2)
		}
	}
	t.normalize()
	return t, r
}

func (v1 *Int) absDiv(v2 *Int) (*Int, *Int) {
	if v2.IsZero() {
		panic("division by zero")
	}
	t1 := v1.clone()
	t2 := v2.clone()
	quotient := Zero.clone()
	// shift t2 until it lines up with t1
	delta := t1.Msb() - t2.Msb()
	if delta < 0 {
		// v2 is larger than v1
		return quotient, t1
	}

	t2.shiftLeftBy(delta)
	for i := 0; i <= delta; i++ {
		t := t1.absSub(t2)
		if t.neg {
			quotient.shiftLeft()
		} else {
			quotient.shiftLeft()
			quotient.v[0] = quotient.v[0] | 1
			t1 = t
		}
		t2.shiftRight()
	}

	return quotient, t1
}

// Mod returns modulus v1%v2 for v2 != 0.
// If v2 == 0, a division-by-zero run-time panic occurs.
func (v1 *Int) Mod(v2 *Int) *Int {
	_, r := v1.Div(v2)
	return r
}

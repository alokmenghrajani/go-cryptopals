package big

// Root returns Nth root of v1. Code adapted from
// https://rosettacode.org/wiki/Integer_roots#int
func (v1 *Int) Root(N int) *Int {
	N2 := NewInt(int64(N))
	for r := NewInt(1); ; {
		x := v1
		for i := 1; i < N; i++ {
			x, _ = x.Div(r)
		}
		x = x.Sub(r)

		// A small complication here is for negative values of x, deltaR
		// needs to be computed as the floor of x / N. We test the remainder and
		// correct the floor division operation (for positive N).
		deltaR, m := x.Div(N2)
		if m.Cmp(Zero) == -1 {
			deltaR = deltaR.Sub(One)
		}
		if deltaR.IsZero() {
			return r
		}
		r = r.Add(deltaR)
	}
}

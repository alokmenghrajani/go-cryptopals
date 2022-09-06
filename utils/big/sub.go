package big

import "github.com/alokmenghrajani/go-cryptopals/utils"

// Sub performs subtraction of two big.Ints
// returns nil if v2 is larger than v1
func (v1 *Int) Sub(v2 *Int) *Int {
	if v1.neg && !v2.neg {
		// -a - +b becomes -(a + b)
		t := v1.absAdd(v2)
		t.neg = true
		return t
	}
	if !v1.neg && v2.neg {
		// +a - -b becomes a + b
		return v1.absAdd(v2)
	}
	if v1.neg && v2.neg {
		// -a - -b becomes b - a
		return v2.absSub(v1)
	}
	// +a - +b remains a - b
	return v1.absSub(v2)
}

func (v1 *Int) absSub(v2 *Int) *Int {
	neg := false
	t1 := v1
	t2 := v2
	if t1.absCmp(t2) == -1 {
		t1, t2 = t2, t1
		neg = true
	}

	r := &Int{v: []uint8{}, neg: neg}
	max := utils.Max(len(t1.v), len(t2.v))
	var carry uint8
	for i := 0; i < max; i++ {
		t := (t1.at(i) - carry - t2.at(i)) & M
		r.v = append(r.v, t)
		if carry == 1 {
			if t >= t1.at(i) {
				carry = 1
			} else {
				carry = 0
			}
		} else {
			if t > t1.at(i) {
				carry = 1
			} else {
				carry = 0
			}
		}
	}
	if carry > 0 {
		// we flipped v2 and v1 so this should never happen
		panic("unreachable")
	}
	r.normalize()
	return r
}

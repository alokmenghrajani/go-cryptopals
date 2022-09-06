package big

import "github.com/alokmenghrajani/go-cryptopals/utils"

// Add performs addition of two big.Ints
func (v1 *Int) Add(v2 *Int) *Int {
	if v1.neg && !v2.neg {
		// -a + +b becomes b - a
		return v2.absSub(v1)
	}
	if !v1.neg && v2.neg {
		// +a + -b becomes a - b
		return v1.absSub(v2)
	}
	if v1.neg && v2.neg {
		// -a + -b becomes -(a + b)
		t := v1.absAdd(v2)
		t.neg = true
		return t
	}
	// +a + +b remains a + b
	return v1.absAdd(v2)
}

// Addition of two numbers. Both numbers are treated as positive numbers.
// The algorithm is the same as what you typically do when using a pen and pencil:
// starting from the least significant element, add pairs of elements and
// keep track of whether a carry has occured or not.
func (v1 *Int) absAdd(v2 *Int) *Int {
	r := &Int{v: []uint8{}}
	max := utils.Max(len(v1.v), len(v2.v))
	var carry uint8
	for i := 0; i < max; i++ {
		t := (carry + v1.at(i) + v2.at(i)) & M
		if carry == 1 {
			if (t <= v1.at(i)) || (t <= v2.at(i)) {
				carry = 1
			} else {
				carry = 0
			}
		} else {
			if (t < v1.at(i)) || (t < v2.at(i)) {
				carry = 1
			} else {
				carry = 0
			}
		}
		r.v = append(r.v, t)
	}
	if carry == 1 {
		r.v = append(r.v, carry)
	}
	return r
}

package big

import "github.com/alokmenghrajani/go-cryptopals/utils"

// Cmp compares v1 and v2 and returns:
//
//	-1 if v1 <  v2
//	 0 if v1 == v2
//	+1 if v1 >  v2
func (v1 *Int) Cmp(v2 *Int) int {
	if v1.neg && !v2.neg {
		return -1
	}
	if !v1.neg && v2.neg {
		return 1
	}
	if v1.neg && v2.neg {
		return -v1.absCmp(v2)
	}
	return v1.absCmp(v2)
}

func (v1 *Int) absCmp(v2 *Int) int {
	max := utils.Max(len(v1.v), len(v2.v))
	for i := max - 1; i >= 0; i-- {
		t1 := v1.at(i)
		t2 := v2.at(i)
		if t1 > t2 {
			return 1
		}
		if t2 > t1 {
			return -1
		}
	}
	return 0
}

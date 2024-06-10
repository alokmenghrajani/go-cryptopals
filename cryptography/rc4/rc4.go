package rc4

type rc4 struct {
	i byte
	j byte
	s [256]byte
}

func New(key []byte) *rc4 {
	rc4 := &rc4{}
	for i := 0; i < 256; i++ {
		rc4.s[i] = byte(i)
	}
	j := byte(0)
	for i := 0; i < 256; i++ {
		j = (j + rc4.s[i] + key[i%len(key)])
		rc4.s[i], rc4.s[j] = rc4.s[j], rc4.s[i]
	}
	return rc4
}

func (rc4 *rc4) Process(input []byte) []byte {
	r := make([]byte, len(input))
	for n := 0; n < len(input); n++ {
		rc4.i++
		rc4.j += rc4.s[rc4.i]
		rc4.s[rc4.i], rc4.s[rc4.j] = rc4.s[rc4.j], rc4.s[rc4.i]
		t := rc4.s[rc4.i] + rc4.s[rc4.j]
		k := rc4.s[t]
		r[n] = k ^ input[n]
	}
	return r
}

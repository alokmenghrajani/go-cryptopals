package utils

import (
	"encoding/binary"
)

// Pure Go implementation of md4 for lolz.
//
// Useful resources:
// https://datatracker.ietf.org/doc/html/rfc1186
// https://datatracker.ietf.org/doc/html/rfc1320
// https://datatracker.ietf.org/doc/html/rfc6150

type md4 struct {
	a       uint32
	b       uint32
	c       uint32
	d       uint32
	buf     []byte
	counter int
}

func NewMd4() *md4 {
	return &md4{
		a:       0x67452301,
		b:       0xefcdab89,
		c:       0x98badcfe,
		d:       0x10325476,
		buf:     []byte{},
		counter: 0,
	}
}

func (m *md4) SetState(a, b, c, d uint32) {
	m.a = a
	m.b = b
	m.c = c
	m.d = d
}

func (m *md4) Update(buf []byte) {
	m.buf = append(m.buf, buf...)
	m.counter += len(buf)
	m.process()
}

func (m *md4) Digest() []byte {
	m.pad()
	m.process()
	if len(m.buf) != 0 {
		panic("left over bytes in buffer")
	}
	r := make([]byte, 16)
	binary.LittleEndian.PutUint32(r, m.a)
	binary.LittleEndian.PutUint32(r[4:], m.b)
	binary.LittleEndian.PutUint32(r[8:], m.c)
	binary.LittleEndian.PutUint32(r[12:], m.d)
	return r
}

func (m *md4) process() {
	x := [16]uint32{}
	for len(m.buf) >= 64 {
		// load X[0]-X[15] with message
		for i := 0; i < 16; i++ {
			x[i] = binary.LittleEndian.Uint32(m.buf[i*4:])
		}
		m.buf = m.buf[64:]

		aa := m.a
		bb := m.b
		cc := m.c
		dd := m.d

		// round 1
		f := func(x, y, z uint32) uint32 {
			return (x & y) | (^x & z)
		}
		ff := func(a, b, c, d uint32, k, s int) uint32 {
			t := f(b, c, d)
			return rotateLeft(a+t+x[k], s)
		}
		m.a = ff(m.a, m.b, m.c, m.d, 0, 3)
		m.d = ff(m.d, m.a, m.b, m.c, 1, 7)
		m.c = ff(m.c, m.d, m.a, m.b, 2, 11)
		m.b = ff(m.b, m.c, m.d, m.a, 3, 19)
		m.a = ff(m.a, m.b, m.c, m.d, 4, 3)
		m.d = ff(m.d, m.a, m.b, m.c, 5, 7)
		m.c = ff(m.c, m.d, m.a, m.b, 6, 11)
		m.b = ff(m.b, m.c, m.d, m.a, 7, 19)
		m.a = ff(m.a, m.b, m.c, m.d, 8, 3)
		m.d = ff(m.d, m.a, m.b, m.c, 9, 7)
		m.c = ff(m.c, m.d, m.a, m.b, 10, 11)
		m.b = ff(m.b, m.c, m.d, m.a, 11, 19)
		m.a = ff(m.a, m.b, m.c, m.d, 12, 3)
		m.d = ff(m.d, m.a, m.b, m.c, 13, 7)
		m.c = ff(m.c, m.d, m.a, m.b, 14, 11)
		m.b = ff(m.b, m.c, m.d, m.a, 15, 19)

		// round 2
		g := func(x, y, z uint32) uint32 {
			return (x & y) | (x & z) | (y & z)
		}
		gg := func(a, b, c, d uint32, k, s int) uint32 {
			return rotateLeft(a+g(b, c, d)+x[k]+0x5A827999, s)
		}
		m.a = gg(m.a, m.b, m.c, m.d, 0, 3)
		m.d = gg(m.d, m.a, m.b, m.c, 4, 5)
		m.c = gg(m.c, m.d, m.a, m.b, 8, 9)
		m.b = gg(m.b, m.c, m.d, m.a, 12, 13)
		m.a = gg(m.a, m.b, m.c, m.d, 1, 3)
		m.d = gg(m.d, m.a, m.b, m.c, 5, 5)
		m.c = gg(m.c, m.d, m.a, m.b, 9, 9)
		m.b = gg(m.b, m.c, m.d, m.a, 13, 13)
		m.a = gg(m.a, m.b, m.c, m.d, 2, 3)
		m.d = gg(m.d, m.a, m.b, m.c, 6, 5)
		m.c = gg(m.c, m.d, m.a, m.b, 10, 9)
		m.b = gg(m.b, m.c, m.d, m.a, 14, 13)
		m.a = gg(m.a, m.b, m.c, m.d, 3, 3)
		m.d = gg(m.d, m.a, m.b, m.c, 7, 5)
		m.c = gg(m.c, m.d, m.a, m.b, 11, 9)
		m.b = gg(m.b, m.c, m.d, m.a, 15, 13)

		// round 3
		h := func(x, y, z uint32) uint32 {
			return x ^ y ^ z
		}
		hh := func(a, b, c, d uint32, k, s int) uint32 {
			return rotateLeft(a+h(b, c, d)+x[k]+0x6ED9EBA1, s)
		}
		m.a = hh(m.a, m.b, m.c, m.d, 0, 3)
		m.d = hh(m.d, m.a, m.b, m.c, 8, 9)
		m.c = hh(m.c, m.d, m.a, m.b, 4, 11)
		m.b = hh(m.b, m.c, m.d, m.a, 12, 15)
		m.a = hh(m.a, m.b, m.c, m.d, 2, 3)
		m.d = hh(m.d, m.a, m.b, m.c, 10, 9)
		m.c = hh(m.c, m.d, m.a, m.b, 6, 11)
		m.b = hh(m.b, m.c, m.d, m.a, 14, 15)
		m.a = hh(m.a, m.b, m.c, m.d, 1, 3)
		m.d = hh(m.d, m.a, m.b, m.c, 9, 9)
		m.c = hh(m.c, m.d, m.a, m.b, 5, 11)
		m.b = hh(m.b, m.c, m.d, m.a, 13, 15)
		m.a = hh(m.a, m.b, m.c, m.d, 3, 3)
		m.d = hh(m.d, m.a, m.b, m.c, 11, 9)
		m.c = hh(m.c, m.d, m.a, m.b, 7, 11)
		m.b = hh(m.b, m.c, m.d, m.a, 15, 15)

		m.a += aa
		m.b += bb
		m.c += cc
		m.d += dd
	}
}

func (m *md4) pad() {
	m.buf = append(m.buf, 0x80)
	n := Remaining(len(m.buf)+8, 64)
	m.buf = append(m.buf, make([]byte, n)...)
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(m.counter*8))
	m.buf = append(m.buf, b...)
}

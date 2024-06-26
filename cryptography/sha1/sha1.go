package sha1

import (
	"encoding/binary"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// Pure Go implementation of sha1 for lolz.
//
// Useful resources:
// https://datatracker.ietf.org/doc/html/rfc3174
// https://nvlpubs.nist.gov/nistpubs/Legacy/FIPS/fipspub180-1.pdf

type sha1 struct {
	h0      uint32
	h1      uint32
	h2      uint32
	h3      uint32
	h4      uint32
	buf     []byte
	counter int
}

func New() *sha1 {
	return &sha1{
		h0:      0x67452301,
		h1:      0xEFCDAB89,
		h2:      0x98BADCFE,
		h3:      0x10325476,
		h4:      0xC3D2E1F0,
		buf:     []byte{},
		counter: 0,
	}
}

func (s *sha1) SetState(h0, h1, h2, h3, h4 uint32) {
	s.h0 = h0
	s.h1 = h1
	s.h2 = h2
	s.h3 = h3
	s.h4 = h4
}

func (s *sha1) Update(buf []byte) {
	s.buf = append(s.buf, buf...)
	s.counter += len(buf)
	s.process()
}

func (s *sha1) Digest() []byte {
	s.pad()
	s.process()
	if len(s.buf) != 0 {
		panic("left over bytes in buffer")
	}
	r := make([]byte, 20)
	binary.BigEndian.PutUint32(r, s.h0)
	binary.BigEndian.PutUint32(r[4:], s.h1)
	binary.BigEndian.PutUint32(r[8:], s.h2)
	binary.BigEndian.PutUint32(r[12:], s.h3)
	binary.BigEndian.PutUint32(r[16:], s.h4)
	return r
}

func (s *sha1) process() {
	w := [80]uint32{}
	f := func(t int, b, c, d uint32) uint32 {
		if t <= 19 {
			return (b & c) | (^b & d)
		} else if t <= 39 {
			return b ^ c ^ d
		} else if t <= 59 {
			return (b & c) | (b & d) | (c & d)
		} else {
			return b ^ c ^ d
		}
	}
	k := func(t int) uint32 {
		if t <= 19 {
			return 0x5A827999
		} else if t <= 39 {
			return 0x6ED9EBA1
		} else if t <= 59 {
			return 0x8F1BBCDC
		} else {
			return 0xCA62C1D6
		}
	}

	for len(s.buf) >= 64 {
		// load W[0]-W[15] with message
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(s.buf[i*4:])
		}
		s.buf = s.buf[64:]

		// compute W[16]-W[79]
		for i := 16; i < 80; i++ {
			w[i] = utils.RotateLeft(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
		}

		a := s.h0
		b := s.h1
		c := s.h2
		d := s.h3
		e := s.h4

		for i := 0; i < 80; i++ {
			t := utils.RotateLeft(a, 5) + f(i, b, c, d) + e + w[i] + k(i)
			e = d
			d = c
			c = utils.RotateLeft(b, 30)
			b = a
			a = t
		}
		s.h0 = s.h0 + a
		s.h1 = s.h1 + b
		s.h2 = s.h2 + c
		s.h3 = s.h3 + d
		s.h4 = s.h4 + e
	}
}

func (s *sha1) pad() {
	s.buf = append(s.buf, 0x80)
	n := utils.Remaining(len(s.buf)+8, 64)
	s.buf = append(s.buf, make([]byte, n)...)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(s.counter*8))
	s.buf = append(s.buf, b...)
}

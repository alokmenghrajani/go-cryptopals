package utils

import (
	"encoding/binary"
)

// Pure Go implementation of sha256 for lolz.
//
// Useful resources:
// https://datatracker.ietf.org/doc/html/rfc6234
// https://en.wikipedia.org/wiki/SHA-2

type sha256 struct {
	h0      uint32
	h1      uint32
	h2      uint32
	h3      uint32
	h4      uint32
	h5      uint32
	h6      uint32
	h7      uint32
	buf     []byte
	counter int
}

func NewSha256() *sha256 {
	return &sha256{
		h0:      0x6a09e667,
		h1:      0xbb67ae85,
		h2:      0x3c6ef372,
		h3:      0xa54ff53a,
		h4:      0x510e527f,
		h5:      0x9b05688c,
		h6:      0x1f83d9ab,
		h7:      0x5be0cd19,
		buf:     []byte{},
		counter: 0,
	}
}

func (s *sha256) Update(buf []byte) {
	s.buf = append(s.buf, buf...)
	s.counter += len(buf)
	s.process()
}

func (s *sha256) Digest() []byte {
	s.pad()
	s.process()
	if len(s.buf) != 0 {
		panic("left over bytes in buffer")
	}
	r := make([]byte, 32)
	binary.BigEndian.PutUint32(r, s.h0)
	binary.BigEndian.PutUint32(r[4:], s.h1)
	binary.BigEndian.PutUint32(r[8:], s.h2)
	binary.BigEndian.PutUint32(r[12:], s.h3)
	binary.BigEndian.PutUint32(r[16:], s.h4)
	binary.BigEndian.PutUint32(r[20:], s.h5)
	binary.BigEndian.PutUint32(r[24:], s.h6)
	binary.BigEndian.PutUint32(r[28:], s.h7)
	return r
}

func (s *sha256) process() {
	k := []uint32{
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
	}
	w := [64]uint32{}
	for len(s.buf) >= 64 {
		// load W[0]-W[15] with message
		for i := 0; i < 16; i++ {
			w[i] = binary.BigEndian.Uint32(s.buf[i*4:])
		}
		s.buf = s.buf[64:]

		// compute W[16]-W[63]
		for i := 16; i < 64; i++ {
			w[i] = ssig1(w[i-2]) + w[i-7] + ssig0(w[i-15]) + w[i-16]
		}

		a := s.h0
		b := s.h1
		c := s.h2
		d := s.h3
		e := s.h4
		f := s.h5
		g := s.h6
		h := s.h7

		for i := 0; i < 64; i++ {
			t1 := h + bsig1(e) + ch(e, f, g) + k[i] + w[i]
			t2 := bsig0(a) + maj(a, b, c)
			h = g
			g = f
			f = e
			e = d + t1
			d = c
			c = b
			b = a
			a = t1 + t2
		}
		s.h0 = s.h0 + a
		s.h1 = s.h1 + b
		s.h2 = s.h2 + c
		s.h3 = s.h3 + d
		s.h4 = s.h4 + e
		s.h5 = s.h5 + f
		s.h6 = s.h6 + g
		s.h7 = s.h7 + h
	}
}

func (s *sha256) pad() {
	s.buf = append(s.buf, 0x80)
	n := Remaining(len(s.buf)+8, 64)
	s.buf = append(s.buf, make([]byte, n)...)
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(s.counter*8))
	s.buf = append(s.buf, b...)
}

func ch(x, y, z uint32) uint32 {
	return (x & y) ^ (^x & z)
}

func maj(x, y, z uint32) uint32 {
	return (x & y) ^ (x & z) ^ (y & z)
}

func bsig0(x uint32) uint32 {
	return rotr(2, x) ^ rotr(13, x) ^ rotr(22, x)
}

func bsig1(x uint32) uint32 {
	return rotr(6, x) ^ rotr(11, x) ^ rotr(25, x)
}

func ssig0(x uint32) uint32 {
	return rotr(7, x) ^ rotr(18, x) ^ (x >> 3)
}

func ssig1(x uint32) uint32 {
	return rotr(17, x) ^ rotr(19, x) ^ (x >> 10)
}

func rotr(n int, v uint32) uint32 {
	return (v >> n) | (v << (32 - n))
}

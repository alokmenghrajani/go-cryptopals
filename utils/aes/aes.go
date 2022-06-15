package aes

import "crypto/cipher"

// An implementation of AES from scratch for fun. The following resources were useful:
// - https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
// - https://blog.nindalf.com/posts/implementing-aes/
// - https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
// - https://en.wikipedia.org/wiki/Rijndael_S-box
// - https://en.wikipedia.org/wiki/Rijndael_MixColumns#Galois_Multiplication_lookup_tables

type aes struct {
	key               [16]byte
	expandedKey       [44]uint
	expandedKeyOffset int
	sbox              [256]byte
	invSbox           [256]byte
	state             [16]byte
}

func NewAes(key []byte) cipher.Block {
	if len(key) != 16 {
		panic("only 16-byte keys are implemented")
	}
	r := aes{}
	copy(r.key[:], key)
	r.initialize()
	return &r
}

func (a aes) BlockSize() int {
	return 16
}

func (a *aes) Encrypt(dst, src []byte) {
	a.keyExpansion()
	if len(src) != 16 {
		panic("invalid input")
	}
	copy(a.state[:], src)

	a.addRoundKey()
	rounds := 9
	for i := 0; i < rounds; i++ {
		a.subBytes()
		a.shiftRows()
		a.mixColumns()
		a.addRoundKey()
	}
	a.subBytes()
	a.shiftRows()
	a.addRoundKey()
	copy(dst, a.state[:])
}

func (a *aes) Decrypt(dst, src []byte) {
	a.keyExpansion()
	if len(src) != 16 {
		panic("invalid input")
	}
	copy(a.state[:], src)

	// so ugly :(
	offset := len(a.expandedKey) - 4
	a.expandedKeyOffset = offset
	offset -= 4
	a.addRoundKey()
	a.invShiftRows()
	a.invSubBytes()
	rounds := 9
	for i := 0; i < rounds; i++ {
		a.expandedKeyOffset = offset
		offset -= 4
		a.addRoundKey()
		a.invMixColumns()
		a.invShiftRows()
		a.invSubBytes()
	}
	a.expandedKeyOffset = offset
	offset -= 4
	a.addRoundKey()
	copy(dst, a.state[:])
}

// sbox initialization
// source: https://en.wikipedia.org/wiki/Rijndael_S-box
func (a *aes) initialize() {
	p := byte(1)
	q := byte(1)

	for {
		// multiply p by 3
		if p&0x80 != 0 {
			p = p ^ (p << 1) ^ 0x1b
		} else {
			p = p ^ (p << 1)
		}

		// divide q by 3 (equals multiplication by 0xf6)
		q ^= q << 1
		q ^= q << 2
		q ^= q << 4
		if q&0x80 != 0 {
			q ^= 0x09
		}

		// compute the affine transformation
		xformed := q ^ rotLeft(q, 1) ^ rotLeft(q, 2) ^ rotLeft(q, 3) ^ rotLeft(q, 4)

		a.sbox[p] = xformed ^ 0x63
		a.invSbox[a.sbox[p]] = p
		if p == 1 {
			break
		}
	}

	// 0 is a special case since it has no inverse
	a.sbox[0] = 0x63
	a.invSbox[0x63] = 0
}

func rotLeft(v, shift byte) byte {
	t := v << shift
	t = t | v>>(8-shift)
	return t
}

func (a *aes) keyExpansion() {
	// copy first 16 bytes of key as-is
	for i := 0; i < 4; i++ {
		a.expandedKey[i] = (uint(a.key[4*i]) << 24) |
			(uint(a.key[4*i+1]) << 16) |
			(uint(a.key[4*i+2]) << 8) |
			uint(a.key[4*i+3])
	}

	// fill remaining bytes
	for i := 4; i < 44; i++ {
		t := a.expandedKey[i-1]
		if i%4 == 0 {
			t = a.subWord(rotWord(t)) ^ rcon(i/4)
		}
		a.expandedKey[i] = a.expandedKey[i-4] ^ t
	}
	a.expandedKeyOffset = 0
}

func (a aes) subWord(v uint) uint {
	b0 := uint(a.sbox[(v>>24)&0xff])
	b1 := uint(a.sbox[(v>>16)&0xff])
	b2 := uint(a.sbox[(v>>8)&0xff])
	b3 := uint(a.sbox[v&0xff])
	return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

func rotWord(v uint) uint {
	b0 := (v >> 24) & 0xff
	b1 := (v >> 16) & 0xff
	b2 := (v >> 8) & 0xff
	b3 := v & 0xff
	return (b1 << 24) | (b2 << 16) | (b3 << 8) | b0
}

func rcon(round int) uint {
	rc := []uint{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36}
	return rc[round-1] << 24
}

func (a *aes) addRoundKey() {
	for i := 0; i < 4; i++ {
		t := a.expandedKeyNext()
		b0 := byte((t >> 24) & 0xff)
		b1 := byte((t >> 16) & 0xff)
		b2 := byte((t >> 8) & 0xff)
		b3 := byte(t & 0xff)
		a.state[4*i] = a.state[4*i] ^ b0
		a.state[4*i+1] = a.state[4*i+1] ^ b1
		a.state[4*i+2] = a.state[4*i+2] ^ b2
		a.state[4*i+3] = a.state[4*i+3] ^ b3
	}
}

func (a *aes) expandedKeyNext() uint {
	t := a.expandedKey[a.expandedKeyOffset]
	a.expandedKeyOffset++
	return t
}

func (a *aes) subBytes() {
	for i := 0; i < 16; i++ {
		a.state[i] = a.sbox[a.state[i]]
	}
}

func (a *aes) shiftRows() {
	// shift by 1
	t := a.state[1]
	a.state[1] = a.state[5]
	a.state[5] = a.state[9]
	a.state[9] = a.state[13]
	a.state[13] = t

	// shift by 2
	a.state[2], a.state[10] = a.state[10], a.state[2]
	a.state[6], a.state[14] = a.state[14], a.state[6]

	// shift by 3
	t = a.state[3]
	a.state[3] = a.state[15]
	a.state[15] = a.state[11]
	a.state[11] = a.state[7]
	a.state[7] = t
}

func (a *aes) mixColumns() {
	for i := 0; i < 4; i++ {
		a.state[4*i], a.state[4*i+1], a.state[4*i+2], a.state[4*i+3] = calcMixColumns(a.state[4*i], a.state[4*i+1], a.state[4*i+2], a.state[4*i+3])
	}
}

func calcMixColumns(a0, a1, a2, a3 byte) (r0, r1, r2, r3 byte) {
	r0 = gMul(2, a0) ^ gMul(3, a1) ^ a2 ^ a3
	r1 = a0 ^ gMul(2, a1) ^ gMul(3, a2) ^ a3
	r2 = a0 ^ a1 ^ gMul(2, a2) ^ gMul(3, a3)
	r3 = gMul(3, a0) ^ a1 ^ a2 ^ gMul(2, a3)
	return
}

// Galois Field (256) Multiplication of two Bytes
// source: https://en.wikipedia.org/wiki/Rijndael_MixColumns#Galois_Multiplication_lookup_tables
func gMul(b1, b2 byte) byte {
	r := byte(0)
	for i := 0; i < 8; i++ {
		if b2&1 != 0 {
			r = r ^ b1
		}
		if b1&0x80 != 0 {
			b1 = (b1 << 1) ^ 0x1b
		} else {
			b1 = b1 << 1
		}
		b2 = b2 >> 1
	}
	return r
}

func (a *aes) invShiftRows() {
	// shift by 1
	t := a.state[1]
	a.state[1] = a.state[13]
	a.state[13] = a.state[9]
	a.state[9] = a.state[5]
	a.state[5] = t

	// shift by 2
	a.state[2], a.state[10] = a.state[10], a.state[2]
	a.state[6], a.state[14] = a.state[14], a.state[6]

	// shift by 3
	t = a.state[3]
	a.state[3] = a.state[7]
	a.state[7] = a.state[11]
	a.state[11] = a.state[15]
	a.state[15] = t
}

func (a *aes) invSubBytes() {
	for i := 0; i < 16; i++ {
		a.state[i] = a.invSbox[a.state[i]]
	}
}

func (a *aes) invMixColumns() {
	for i := 0; i < 4; i++ {
		a.state[4*i], a.state[4*i+1], a.state[4*i+2], a.state[4*i+3] = calcInvMixColumns(a.state[4*i], a.state[4*i+1], a.state[4*i+2], a.state[4*i+3])
	}
}

func calcInvMixColumns(a0, a1, a2, a3 byte) (r0, r1, r2, r3 byte) {
	r0 = gMul(14, a0) ^ gMul(11, a1) ^ gMul(13, a2) ^ gMul(9, a3)
	r1 = gMul(9, a0) ^ gMul(14, a1) ^ gMul(11, a2) ^ gMul(13, a3)
	r2 = gMul(13, a0) ^ gMul(9, a1) ^ gMul(14, a2) ^ gMul(11, a3)
	r3 = gMul(11, a0) ^ gMul(13, a1) ^ gMul(9, a2) ^ gMul(14, a3)
	return
}

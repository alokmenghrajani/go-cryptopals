package pkcs1_5

import (
	"crypto/rand"
	"errors"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// Pads buffer using pkcs#1.5
// the padding scheme is documented here:
// https://datatracker.ietf.org/doc/html/rfc2313#section-8.1
func Pad(buf []byte, k int) []byte {
	if k < 12 {
		panic("k is too small for pkcs v1.5 padding")
	}
	if len(buf) > k-11 {
		panic("buf is too large for pkcs v1.5 padding")
	}
	r := make([]byte, 0, k)
	r = append(r, 0x00)
	r = append(r, 0x02)
	for i := 0; i < k-3-len(buf); i++ {
		// generate random padding, but the padding can't contain 0x00
		for {
			b := []byte{0x00}
			_, err := rand.Read(b)
			utils.PanicOnErr(err)
			if b[0] != 0x00 {
				r = append(r, b[0])
				break
			}
		}
	}
	r = append(r, 0x00)
	r = append(r, buf...)
	return r
}

// Unpads buffer assuming buffer is padding with pkcs#1.5.
func Unpad(buf []byte, k int) ([]byte, error) {
	r := buf
	if r[0] != 0x00 {
		return nil, errors.New("first byte is not 0x00")
	}
	r = r[1:]

	if r[0] != 0x02 {
		return nil, errors.New("second byte is not 0x02")
	}
	r = r[1:]

	paddingLength := 0
	for r[0] != 0x00 {
		r = r[1:]
		paddingLength += 1
		if len(r) == 0 {
			return nil, errors.New("did not find end of padding")
		}
	}
	if paddingLength < 8 {
		return nil, errors.New("padding is too short")
	}
	r = r[1:]

	return r, nil
}

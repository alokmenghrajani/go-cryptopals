package hmacSha1

import (
	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha1"
)

// See https://en.wikipedia.org/wiki/HMAC
func Compute(key, msg []byte) []byte {
	// compute key2 (k')
	var key2 []byte
	if len(key) > 64 {
		s := sha1.New()
		s.Update(key)
		key2 = s.Digest()
	} else {
		key2 = key
	}
	for len(key2) < 64 {
		key2 = append(key2, 0)
	}

	// inner hash: H((k' ^ 0x36) || m)
	innerKey := make([]byte, 64)
	for i := 0; i < 64; i++ {
		innerKey[i] = key2[i] ^ 0x36
	}
	s := sha1.New()
	s.Update(innerKey)
	s.Update(msg)
	innerHash := s.Digest()

	// outer hash: H((k' ^ 0x5c) || innerHash)
	outerKey := make([]byte, 64)
	for i := 0; i < 64; i++ {
		outerKey[i] = key2[i] ^ 0x5c
	}
	s = sha1.New()
	s.Update(outerKey)
	s.Update(innerHash)
	return s.Digest()
}

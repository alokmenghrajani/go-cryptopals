package pkcs7

import "errors"

// pad buffer using pkcs#7
// the padding scheme is documented here:
// https://datatracker.ietf.org/doc/html/rfc2315#section-10.3
func Pad(buf []byte, blockSize int) []byte {
	if blockSize < 1 || blockSize > 255 {
		panic("invalid blocksize")
	}
	paddingSize := blockSize - (len(buf) % blockSize)
	for i := 0; i < paddingSize; i++ {
		buf = append(buf, byte(paddingSize))
	}
	return buf
}

// assumes buffer is padded with pkcs#7 and strips the padding
func Unpad(buf []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 255 {
		return nil, errors.New("invalid blocksize")
	}
	paddingSize := int(buf[len(buf)-1])
	if paddingSize == 0 || paddingSize > blockSize {
		return nil, errors.New("invalid padding")
	}
	for i := len(buf) - paddingSize; i < len(buf); i++ {
		if buf[i] != byte(paddingSize) {
			return nil, errors.New("invalid padding")
		}
	}

	return buf[0 : len(buf)-paddingSize], nil
}

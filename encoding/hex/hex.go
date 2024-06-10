package hex

import "fmt"

// Converts a hex string to []byte. Panics if the input's length isn't even
// or if the input contains invalid characters.
func ToByteSlice(s string) []byte {
	// check that input is a multiple of two
	if (len(s) % 2) != 0 {
		panic("invalid hex")
	}

	// allocate space to convert hex to bytes
	buf := make([]byte, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		// convert hex pair to byte
		buf = append(buf, hexToByte(s[i:i+2]))
	}
	return buf
}

// converts two-character hex to a byte
func hexToByte(s string) byte {
	v := hexToNibble(s[0]) * 16
	v += hexToNibble(s[1])
	return v
}

// converts one-character hex to a nibble (i.e. half a byte)
func hexToNibble(s byte) byte {
	if s >= '0' && s <= '9' {
		return s - '0'
	} else if s >= 'a' && s <= 'f' {
		return s - 'a' + 10
	}
	panic(fmt.Errorf("invalid hex: %c", s))
}

// Converts []byte to hex-encoded string.
func FromByteSlice(buf []byte) string {
	r := make([]byte, 0, len(buf)*2)
	for i := 0; i < len(buf); i++ {
		r = append(r, byteToHex(buf[i])...)
	}
	return string(r)
}

// converts a byte to hex-encoded string.
func byteToHex(buf byte) string {
	r := []byte{0, 0}
	r[0] = nibbleToHex((buf >> 4) & 0xf)
	r[1] = nibbleToHex(buf & 0xf)
	return string(r)
}

// converts a nibble (i.e. half a byte) to a hex-character
func nibbleToHex(buf byte) byte {
	if buf < 10 {
		return '0' + buf
	} else if buf < 16 {
		return 'a' + buf - 10
	} else {
		panic("something is wrong")
	}
}

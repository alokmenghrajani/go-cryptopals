package utils

import "strings"

// base64 encoding
func ByteSliceToBase64(buf []byte) string {
	// calculate how much space we'll need
	n := int(len(buf) * 4 / 3)
	var extra int
	if (len(buf) % 3) != 0 {
		extra = 3 - (len(buf) % 3)
		n += extra
	}

	// convert bytes to base64
	output := make([]byte, 0, n)
	bitBuffer := newBitBuffer(buf)
	for i := 0; i < len(buf)*8; i += 6 {
		// read 6 bits
		t := bitBuffer.read(6)
		output = append(output, bitsToBase64(t))
	}
	for i := 0; i < extra; i++ {
		output = append(output, '=')
	}

	return string(output)
}

// converts a 6-bit value to a base64 character
func bitsToBase64(v byte) byte {
	if v < 26 {
		return 'A' + v
	}
	if v < 52 {
		return 'a' + v - 26
	}
	if v < 62 {
		return '0' + v - 52
	}
	if v == 62 {
		return '+'
	}
	if v == 63 {
		return '/'
	}
	panic("something is wrong")
}

// base64 decoding
func Base64ToByteSlice(input string) []byte {
	if (len(input) % 4) != 0 {
		panic("invalid input")
	}
	finalLen := len(input) / 4 * 3
	if strings.HasSuffix(input, "=") {
		finalLen--
		if strings.HasSuffix(input, "==") {
			finalLen--
		}
	}
	bitBuffer := newEmptyBitBuffer(finalLen)

	// iterate over the input and emit 6 bits for every byte
	for i := 0; i < len(input); i++ {
		if input[i] >= 'A' && input[i] <= 'Z' {
			bitBuffer.write(input[i]-'A', 6)
		} else if input[i] >= 'a' && input[i] <= 'z' {
			bitBuffer.write(input[i]-'a'+26, 6)
		} else if input[i] >= '0' && input[i] <= '9' {
			bitBuffer.write(input[i]-'0'+52, 6)
		} else if input[i] == '+' {
			bitBuffer.write(62, 6)
		} else if input[i] == '/' {
			bitBuffer.write(63, 6)
		} else if input[i] == '=' {
			break
		} else {
			panic("invalid input")
		}
	}

	return bitBuffer.buf[0:finalLen]
}

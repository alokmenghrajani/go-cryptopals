package base64

import (
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

// base64 encodes buf per https://www.rfc-editor.org/rfc/rfc4648
func FromByteSlice(buf []byte) string {
	// Calculate how much space we'll need. Every 3 characters gets encoded
	// as 4 characters. The formula is 4 * ceil(buf/3) but we do a +1 and -1
	// trick so that the whole computation remains integer without having to
	// deal with floats.
	n := 4 * (1 + (len(buf)-1)/3)
	output := make([]byte, 0, n)
	bitBuffer := utils.NewBitBuffer(buf)
	for i := 0; i < len(buf)*8; i += 6 {
		// read 6 bits
		t := bitBuffer.Read(6)
		output = append(output, bitsToBase64(t))
	}

	// Add the padding
	extra := utils.Remaining(len(buf), 3)
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

// base64 decodes input
func ToByteSlice(input string) []byte {
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
	bitBuffer := utils.NewEmptyBitBuffer(finalLen)

	// iterate over the input and emit 6 bits for every byte
	for i := 0; i < len(input); i++ {
		if input[i] >= 'A' && input[i] <= 'Z' {
			bitBuffer.Write(input[i]-'A', 6)
		} else if input[i] >= 'a' && input[i] <= 'z' {
			bitBuffer.Write(input[i]-'a'+26, 6)
		} else if input[i] >= '0' && input[i] <= '9' {
			bitBuffer.Write(input[i]-'0'+52, 6)
		} else if input[i] == '+' {
			bitBuffer.Write(62, 6)
		} else if input[i] == '/' {
			bitBuffer.Write(63, 6)
		} else if input[i] == '=' {
			break
		} else {
			panic("invalid input")
		}
	}

	return bitBuffer.Buffer[0:finalLen]
}

package utils

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRead(t *testing.T) {
	buf := newBitBuffer([]byte{0b00111010, 0b01011100})
	r := []byte{0b001, 0b110, 0b100, 0b101, 0b110, 0b000, 0b000}
	for i := 0; i < len(r); i++ {
		require.Equal(t, r[i], buf.read(3), fmt.Sprintf("i=%d", i))
	}
}

func TestWrite(t *testing.T) {
	buf := newEmptyBitBuffer(0)
	r := []byte{0b001, 0b110, 0b100, 0b101, 0b110, 0b000, 0b000}
	for i := 0; i < len(r); i++ {
		buf.write(r[i], 3)
	}
	require.Equal(t, byte(0b00111010), buf.buf[0])
	require.Equal(t, byte(0b01011100), buf.buf[1])
}

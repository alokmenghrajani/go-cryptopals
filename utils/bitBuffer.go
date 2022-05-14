package utils

// wraps a []byte and provides functions to read/write specific number of bits.
// writing past the end of the buffer grows the buffer.
// reading past the end of the buffer returns 0.
type bitBuffer struct {
	buf       []byte
	nextWrite int
	nextRead  int
}

func newEmptyBitBuffer(capacity int) *bitBuffer {
	return &bitBuffer{
		buf: make([]byte, 0, capacity),
	}
}

func newBitBuffer(buf []byte) *bitBuffer {
	return &bitBuffer{
		buf:       buf,
		nextWrite: len(buf) * 8,
	}
}

func (buf *bitBuffer) read(bits int) byte {
	r := byte(0)
	for i := 0; i < bits; i++ {
		majorOffset := buf.nextRead / 8
		minorOffset := buf.nextRead % 8
		v := byte(0)
		if majorOffset < len(buf.buf) {
			v = buf.buf[majorOffset] >> (7 - minorOffset)
		}
		r = (r << 1) | (v & 1)
		buf.nextRead++
	}
	return r
}

func (buf *bitBuffer) write(v byte, bits int) {
	for i := 0; i < bits; i++ {
		majorOffset := buf.nextWrite / 8
		minorOffset := buf.nextWrite % 8
		for majorOffset >= len(buf.buf) {
			buf.buf = append(buf.buf, 0)
		}
		t := v >> (bits - i - 1)
		t = (t & 1) << (7 - minorOffset)
		buf.buf[majorOffset] = buf.buf[majorOffset] | t
		buf.nextWrite++
	}
}

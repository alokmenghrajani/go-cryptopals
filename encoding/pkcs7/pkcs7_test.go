package pkcs7

import (
	"fmt"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/require"
)

func TestPadding(t *testing.T) {
	rng := rng.New()

	for n := 0; n < 1000; n++ {
		blockSize := rng.Int(255) + 1

		for i := 0; i < 300; i++ {
			buf := rng.Bytes(i)

			buf2 := Pad(buf, blockSize)
			require.Equal(t, 0, len(buf2)%blockSize, fmt.Sprintf("blockSize=%d, i=%d", blockSize, i))
			buf2, err := Unpad(buf2, blockSize)
			require.Nil(t, err)
			require.Equal(t, buf, buf2, fmt.Sprintf("blockSize=%d, i=%d", blockSize, i))
		}
	}
}

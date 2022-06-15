package utils

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPadding(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)

	for n := 0; n < 1000; n++ {
		blockSize := rand.Intn(255) + 1

		for i := 0; i < 300; i++ {
			buf := make([]byte, 0, i)
			rand.Read(buf)

			buf2 := Pad(buf, blockSize)
			require.Equal(t, 0, len(buf2)%blockSize, fmt.Sprintf("seed=%d, blockSize=%d, i=%d", seed, blockSize, i))
			buf2, err := Unpad(buf2, blockSize)
			require.Nil(t, err)
			require.Equal(t, buf, buf2, fmt.Sprintf("seed=%d, blockSize=%d, i=%d", seed, blockSize, i))
		}
	}
}

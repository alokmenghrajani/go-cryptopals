package pkcs1_5

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPadding(t *testing.T) {
	k := 32
	shortString := "foo bar"
	shortStringPadded := Pad([]byte(shortString), k)
	shortStringRoundtrip, err := Unpad(shortStringPadded, k)
	require.Nil(t, err)
	require.Equal(t, shortString, string(shortStringRoundtrip))

	shortStringPadded[0] = 0x11
	_, err = Unpad(shortStringPadded, k)
	require.NotNil(t, err)
	require.Equal(t, "first byte is not 0x00", err.Error())

	shortStringPadded[0] = 0x00
	shortStringPadded[1] = 0x00
	_, err = Unpad(shortStringPadded, k)
	require.NotNil(t, err)
	require.Equal(t, "second byte is not 0x02", err.Error())

	shortStringPadded[1] = 0x02
	shortStringPadded[24] = 0x01
	_, err = Unpad(shortStringPadded, k)
	require.NotNil(t, err)
	require.Equal(t, "did not find end of padding", err.Error())

	shortStringPadded[24] = 0x00
	shortStringPadded[3] = 0x00
	_, err = Unpad(shortStringPadded, k)
	require.NotNil(t, err)
	require.Equal(t, "padding is too short", err.Error())

	seed := time.Now().Unix()
	rng := rand.New(rand.NewSource(seed))

	for i := 0; i < 300; i++ {
		for n := 0; n < 1000; n++ {
			buf := make([]byte, 0, i)
			rng.Read(buf)

			buf2 := Pad(buf, k)
			require.Equal(t, k, len(buf2), fmt.Sprintf("seed=%d, k=%d, i=%d, n=%d", seed, k, i, n))
			buf2, err := Unpad(buf2, k)
			require.Nil(t, err)
			require.Equal(t, buf, buf2, fmt.Sprintf("seed=%d, k=%d, i=%d, n=%d", seed, k, i, n))
		}
	}
}

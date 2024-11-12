package pkcs1_5

import (
	"fmt"
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/require"
)

func TestPadding(t *testing.T) {
	rng := rng.New()

	k := 32
	shortString := "foo bar"
	shortStringPadded := Pad(rng, []byte(shortString), k)
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

	for i := 0; i < 22; i++ {
		for n := 0; n < 1000; n++ {
			buf := rng.Bytes(i)
			buf2 := Pad(rng, buf, k)
			require.Equal(t, k, len(buf2), fmt.Sprintf("k=%d, i=%d, n=%d", k, i, n))
			buf2, err := Unpad(buf2, k)
			require.Nil(t, err)
			require.Equal(t, buf, buf2, fmt.Sprintf("k=%d, i=%d, n=%d", k, i, n))
		}
	}
}

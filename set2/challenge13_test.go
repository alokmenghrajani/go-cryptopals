package set2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseString(t *testing.T) {
	r := parseString("foo=bar&baz=qux&zap=zazzle")
	require.Equal(t, r, map[string]string{"foo": "bar", "baz": "qux", "zap": "zazzle"})
}

func TestEncode(t *testing.T) {
	r := encode(map[string]string{"email": "bar", "uid": "qux", "role": "zazzle"})
	require.Equal(t, r, "email=bar&uid=qux&role=zazzle")

	r = encode(map[string]string{"email": "foo@bar.com&role=admin"})
	require.Equal(t, r, "email=foo@bar.com_role_admin&uid=&role=")

}

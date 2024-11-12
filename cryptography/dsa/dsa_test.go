package dsa

import (
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/stretchr/testify/assert"
)

func TestDsaSigning(t *testing.T) {
	pubKey, privKey := GenerateKeyPair(DefaultParams())
	msg := []byte("hello world")

	signature := privKey.Sign(nil, msg)
	assert.True(t, pubKey.Verify(msg, signature))

	signature.R.Add(signature.R, bigutils.One)
	assert.False(t, pubKey.Verify(msg, signature))

	signature.R.Sub(signature.R, bigutils.One)
	signature.S.Add(signature.R, bigutils.One)
	assert.False(t, pubKey.Verify(msg, signature))
}

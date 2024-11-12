package dsa

import (
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/stretchr/testify/assert"
)

func TestDsaSigning(t *testing.T) {
	rng := rng.New()
	pubKey, privKey := GenerateKeyPair(rng, DefaultParams())
	msg := []byte("hello world")

	signature := privKey.Sign(rng, nil, msg)
	assert.True(t, pubKey.Verify(msg, signature))

	signature.R.Add(signature.R, bigutils.One)
	assert.False(t, pubKey.Verify(msg, signature))

	signature.R.Sub(signature.R, bigutils.One)
	signature.S.Add(signature.R, bigutils.One)
	assert.False(t, pubKey.Verify(msg, signature))
}

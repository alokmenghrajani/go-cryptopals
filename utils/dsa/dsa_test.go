package dsa

import (
	"testing"

	"github.com/alokmenghrajani/go-cryptopals/utils/big"
	"github.com/stretchr/testify/assert"
)

func TestDsaSigning(t *testing.T) {
	pubKey, privKey := GenerateKeyPair()
	msg := []byte("hello world")

	signature := privKey.Sign(msg)
	assert.True(t, pubKey.Verify(msg, signature))

	signature.R = signature.R.Add(big.One)
	assert.False(t, pubKey.Verify(msg, signature))

	signature.R = signature.R.Sub(big.One)
	signature.S = signature.S.Add(big.One)
	assert.False(t, pubKey.Verify(msg, signature))
}

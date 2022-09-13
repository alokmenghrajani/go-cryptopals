package dsa

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDsaSigning(t *testing.T) {
	pubKey, privKey := GenerateKeyPair(DefaultParams())
	msg := []byte("hello world")

	signature := privKey.Sign(nil, msg)
	assert.True(t, pubKey.Verify(msg, signature))

	signature.R.Add(signature.R, big.NewInt(1))
	assert.False(t, pubKey.Verify(msg, signature))

	signature.R.Sub(signature.R, big.NewInt(1))
	signature.S.Add(signature.R, big.NewInt(1))
	assert.False(t, pubKey.Verify(msg, signature))
}

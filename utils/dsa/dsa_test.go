package dsa

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDsaSigning(t *testing.T) {
	pubKey, privKey := GenerateKeyPair()
	msg := []byte("hello world")

	signature := privKey.Sign(msg)
	assert.True(t, pubKey.Verify(msg, signature))

	signature.r.Add(signature.r, big.NewInt(1))
	assert.False(t, pubKey.Verify(msg, signature))

	signature.r.Sub(signature.r, big.NewInt(1))
	signature.s.Add(signature.r, big.NewInt(1))
	assert.False(t, pubKey.Verify(msg, signature))
}

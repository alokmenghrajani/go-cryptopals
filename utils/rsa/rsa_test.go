package rsa

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRsa(t *testing.T) {
	pubKey, privKey := GenerateKeyPair(256)
	msg := "hello world"
	ciphertext := pubKey.Encrypt([]byte(msg))
	plaintext := privKey.Decrypt(ciphertext)
	assert.Equal(t, msg, string(plaintext))
}

package rsa

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRsaEncryption(t *testing.T) {
	// Check that an encryption + decryption roundtrip returns original data
	pubKey, privKey := GenerateKeyPair(256)
	msg := "hello world"
	ciphertext := pubKey.Encrypt([]byte(msg))
	plaintext := privKey.Decrypt(ciphertext)
	assert.Equal(t, msg, string(plaintext))
}

func TestRsaSigning(t *testing.T) {
	seed := time.Now().Unix()
	rand.Seed(seed)

	// Check that verifying signatures works for a simple static case
	pubKey, privKey := GenerateKeyPair(256)
	msg := []byte("hello world")
	signature := privKey.Sign(msg)
	verification := pubKey.Verify(signature)
	assert.Equal(t, msg, verification)

	// Mutate a random byte in the signature and check that pubKey.Verify fails
	randomByte := rand.Intn(len(signature))
	randomPattern := rand.Intn(0xff) + 1
	signature[randomByte] = signature[randomByte] ^ byte(randomPattern)
	verification = pubKey.Verify(signature)
	assert.NotEqual(t, msg, verification, fmt.Sprintf("seed=%d", seed))
}

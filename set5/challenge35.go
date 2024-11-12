package set5

import (
	"fmt"
	"math/big"

	"github.com/alokmenghrajani/go-cryptopals/bigutils"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha1"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge35(rng *rng.Rng) {
	utils.PrintTitle(5, 35)

	p := bigutils.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	g := big.NewInt(5)

	withNegotiatedGroups(rng, p, g)
	withNegotiatedGroupsMitm(rng, "hello world 1", p, g, bigutils.One, bigutils.One)
	withNegotiatedGroupsMitm(rng, "hello world 2", p, g, p, bigutils.Zero)

	// Replacing A with g2 will only work 50% of the time as B will fail to
	// decrypt A's message 50% of the time when the session value is 1 instead of p-1.
	// So the code is commented out...
	// p2 := &big.Int{}
	// p2.Set(p)
	// p2.Sub(p2, bigutils.One)
	// withNegotiatedGroupsMitm("hello world 3", p, g, p2, p2)

	fmt.Println()
}

func withNegotiatedGroups(rng *rng.Rng, p, g *big.Int) {
	// A: generates a key
	a := rng.BigInt(p)
	A := &big.Int{}
	A.Exp(g, a, p)

	// establish key
	bot := newEchoBot(rng, p, g, A)
	B := bot.PubKey()
	s := &big.Int{}
	s.Exp(B, a, p)
	sha := sha1.New()
	sha.Update(s.Bytes())
	key := sha.Digest()[0:16]

	// encrypt message
	msg := "hello world"
	iv := rng.Bytes(aes.BlockSize)
	ciphertext := aes.AesCbcEncrypt(pkcs7.Pad([]byte(msg), aes.BlockSize), key, iv)

	// send ciphertext to bot
	bytes := []byte{}
	bytes = append(bytes, iv...)
	bytes = append(bytes, ciphertext...)
	responseCiphertext := bot.Echo(rng, bytes)

	// decrypt response
	responsePlaintext, err := pkcs7.Unpad(aes.AesCbcDecrypt(responseCiphertext[aes.BlockSize:], key, responseCiphertext[0:aes.BlockSize]), aes.BlockSize)
	utils.PanicOnErr(err)
	fmt.Println(string(responsePlaintext))
	fmt.Println()
}

func withNegotiatedGroupsMitm(rng *rng.Rng, msg string, p, g, g2, expectedS *big.Int) {
	// A: generates a key
	a := rng.BigInt(p)
	A := &big.Int{}
	A.Exp(g, a, p)

	// establish key
	bot := newEchoBot(rng, p, g2, g2) // MITM replaces g and A with g2
	B := bot.PubKey()
	s := &big.Int{}
	s.Exp(B, a, p)
	sha := sha1.New()
	sha.Update(s.Bytes())
	key := sha.Digest()[0:16]

	// encrypt message
	iv := rng.Bytes(aes.BlockSize)
	ciphertext := aes.AesCbcEncrypt(pkcs7.Pad([]byte(msg), aes.BlockSize), key, iv)

	// send ciphertext to bot
	bytes := []byte{}
	bytes = append(bytes, iv...)
	bytes = append(bytes, ciphertext...)
	responseCiphertext := bot.Echo(rng, bytes)

	// MITM decrypts both ciphertexts
	sha = sha1.New()
	sha.Update(expectedS.Bytes())
	key = sha.Digest()[0:16]
	plaintext, err := pkcs7.Unpad(aes.AesCbcDecrypt(bytes[aes.BlockSize:], key, bytes[0:aes.BlockSize]), aes.BlockSize)
	utils.PanicOnErr(err)
	fmt.Println(string(plaintext))

	plaintext, err = pkcs7.Unpad(aes.AesCbcDecrypt(responseCiphertext[aes.BlockSize:], key, responseCiphertext[0:aes.BlockSize]), aes.BlockSize)
	utils.PanicOnErr(err)
	fmt.Println(string(plaintext))

	fmt.Println()
}

package set5

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/sha1"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

func Challenge35() {
	utils.PrintTitle(5, 35)

	rand.Seed(time.Now().Unix())

	var p big.Int
	_, ok := p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	if !ok {
		panic("SetString failed")
	}
	g := big.NewInt(5)

	withNegotiatedGroups(&p, g)
	withNegotiatedGroupsMitm("hello world 1", &p, g, big.NewInt(1), big.NewInt(1))
	withNegotiatedGroupsMitm("hello world 2", &p, g, &p, big.NewInt(0))

	// Replacing A with g2 will only work 50% of the time as B will fail to
	// decrypt A's message 50% of the time when the session value is 1 instead of p-1.
	// So the code is commented out...
	// var p2 big.Int
	// p2.Set(&p)
	// p2.Sub(&p2, big.NewInt(1))
	// withNegotiatedGroupsMitm("hello world 3", &p, g, &p2, &p2)

	fmt.Println()
}

func withNegotiatedGroups(p, g *big.Int) {
	// A: generates a key
	a := big.NewInt(int64(rand.Int()))
	a.Mod(a, p)
	var A big.Int
	A.Exp(g, a, p)

	// establish key
	bot := newEchoBot(p, g, &A)
	B := bot.PubKey()
	var s big.Int
	s.Exp(B, a, p)
	sha := sha1.New()
	sha.Update(s.Bytes())
	key := sha.Digest()[0:16]

	// encrypt message
	msg := "hello world"
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	utils.PanicOnErr(err)
	ciphertext := aes.AesCbcEncrypt(pkcs7.Pad([]byte(msg), 16), key, iv)

	// send ciphertext to bot
	bytes := []byte{}
	bytes = append(bytes, iv...)
	bytes = append(bytes, ciphertext...)
	responseCiphertext := bot.Echo(bytes)

	// decrypt response
	responsePlaintext, err := pkcs7.Unpad(aes.AesCbcDecrypt(responseCiphertext[16:], key, responseCiphertext[0:16]), 16)
	utils.PanicOnErr(err)
	fmt.Println(string(responsePlaintext))
	fmt.Println()
}

func withNegotiatedGroupsMitm(msg string, p, g, g2, expectedS *big.Int) {
	// A: generates a key
	a := big.NewInt(int64(rand.Int()))
	a.Mod(a, p)
	var A big.Int
	A.Exp(g, a, p)

	// establish key
	bot := newEchoBot(p, g2, g2) // MITM replaces g and A with g2
	B := bot.PubKey()
	var s big.Int
	s.Exp(B, a, p)
	sha := sha1.New()
	sha.Update(s.Bytes())
	key := sha.Digest()[0:16]

	// encrypt message
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	utils.PanicOnErr(err)
	ciphertext := aes.AesCbcEncrypt(pkcs7.Pad([]byte(msg), 16), key, iv)

	// send ciphertext to bot
	bytes := []byte{}
	bytes = append(bytes, iv...)
	bytes = append(bytes, ciphertext...)
	responseCiphertext := bot.Echo(bytes)

	// MITM decrypts both ciphertexts
	sha = sha1.New()
	sha.Update(expectedS.Bytes())
	key = sha.Digest()[0:16]
	plaintext, err := pkcs7.Unpad(aes.AesCbcDecrypt(bytes[16:], key, bytes[0:16]), 16)
	utils.PanicOnErr(err)
	fmt.Println(string(plaintext))

	plaintext, err = pkcs7.Unpad(aes.AesCbcDecrypt(responseCiphertext[16:], key, responseCiphertext[0:16]), 16)
	utils.PanicOnErr(err)
	fmt.Println(string(plaintext))

	fmt.Println()
}

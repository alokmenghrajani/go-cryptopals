package set5

import (
	"fmt"
	"math/big"
	"math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

type echoBot struct {
	p *big.Int
	g *big.Int
	b *big.Int
	A *big.Int
	B *big.Int
}

func Challenge34() {
	utils.PrintTitle(5, 34)

	rand.Seed(time.Now().Unix())

	withoutMitm()
	withMitm()

	fmt.Println()
}

func withoutMitm() {
	// A: generates a key
	var p big.Int
	_, ok := p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	if !ok {
		panic("SetString failed")
	}
	g := big.NewInt(5)

	a := big.NewInt(int64(rand.Int()))
	a.Mod(a, &p)
	var A big.Int
	A.Exp(g, a, &p)

	// establish key
	bot := newEchoBot(&p, g, &A)
	B := bot.PubKey()
	var s big.Int
	s.Exp(B, a, &p)
	sha := utils.NewSha1()
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

func withMitm() {
	// A: generates a key
	var p big.Int
	_, ok := p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	if !ok {
		panic("SetString failed")
	}
	g := big.NewInt(5)

	a := big.NewInt(int64(rand.Int()))
	a.Mod(a, &p)
	var A big.Int
	A.Exp(g, a, &p)

	// establish key
	bot := newEchoBot(&p, g, &p) // MITM replaces A with p
	B := &p                      // MITM replaces B with p
	var s big.Int
	s.Exp(B, a, &p)
	sha := utils.NewSha1()
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

	// MITM decrypts both ciphertexts
	sha = utils.NewSha1()
	sha.Update(big.NewInt(0).Bytes())
	key = sha.Digest()[0:16]
	plaintext, err := pkcs7.Unpad(aes.AesCbcDecrypt(bytes[16:], key, bytes[0:16]), 16)
	utils.PanicOnErr(err)
	fmt.Println(string(plaintext))

	plaintext, err = pkcs7.Unpad(aes.AesCbcDecrypt(responseCiphertext[16:], key, responseCiphertext[0:16]), 16)
	utils.PanicOnErr(err)
	fmt.Println(string(plaintext))

	fmt.Println()
}

func newEchoBot(p, g, A *big.Int) *echoBot {
	b := big.NewInt(int64(rand.Int()))
	b.Mod(b, p)
	var B big.Int
	B.Exp(g, b, p)

	return &echoBot{
		p: p,
		g: g,
		b: b,
		A: A,
		B: &B,
	}
}

func (bot *echoBot) PubKey() *big.Int {
	return bot.B
}

func (bot *echoBot) Echo(ciphertext []byte) []byte {
	// establish key
	var s big.Int
	s.Exp(bot.A, bot.b, bot.p)
	sha := utils.NewSha1()
	sha.Update(s.Bytes())
	key := sha.Digest()[0:16]

	// decrypt message
	t := aes.AesCbcDecrypt(ciphertext[16:], key, ciphertext[0:16])
	plaintext, err := pkcs7.Unpad(t, 16)
	utils.PanicOnErr(err)

	// encrypt response
	newPlaintext := []byte("re: ")
	newPlaintext = append(newPlaintext, plaintext...)
	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	utils.PanicOnErr(err)
	ciphertext2 := aes.AesCbcEncrypt(pkcs7.Pad(newPlaintext, 16), key, iv)
	bytes := []byte{}
	bytes = append(bytes, iv...)
	bytes = append(bytes, ciphertext2...)
	return bytes
}

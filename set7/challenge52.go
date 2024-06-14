package set7

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"sort"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge52() {
	utils.PrintTitle(7, 52)

	fmt.Println("H1 is a 16-bit hash")
	fmt.Println("demonstration of 32-way collision with ~1280 calls to H.")
	msgs, cost := findMultiCollisions(5)
	sort.Slice(msgs, func(i, j int) bool {
		return bytes.Compare(msgs[i], msgs[j]) <= 0
	})
	for i := 0; i < len(msgs); i++ {
		h1 := MD1(msgs[i])
		fmt.Printf("%2d %s %s\n", i, hex.FromByteSlice(msgs[i]), hex.FromByteSlice(h1))
	}
	fmt.Printf("calls to H1: %d\n", cost)
	fmt.Println()

	fmt.Println("H2 is a 24-bit hash")
	fmt.Println("demonstration of breaking H1(...) || H2(...)")
	left, right, cost1, cost2 := findPairCollision()
	h1 := MD1(left)
	h2 := MD2(left)
	fmt.Printf("%s %s %s\n", hex.FromByteSlice(left), hex.FromByteSlice(h1), hex.FromByteSlice(h2))

	h1 = MD1(right)
	h2 = MD2(right)
	fmt.Printf("%s %s %s\n", hex.FromByteSlice(right), hex.FromByteSlice(h1), hex.FromByteSlice(h2))
	fmt.Printf("calls to H1: %d\n", cost1)
	fmt.Printf("calls to H2: %d\n", cost2)
	fmt.Println()
}

func C1(buf []byte, key []byte) []byte {
	aesKey := []byte{}
	for i := 0; i < 8; i++ {
		aesKey = append(aesKey, key...)
	}
	aesCipher := aes.NewAes(aesKey)
	r := make([]byte, aes.BlockSize)
	aesCipher.Encrypt(r, buf)
	return r[0:2]
}

func MD1(msg []byte) []byte {
	msg = pkcs7.Pad(msg, aes.BlockSize)
	h := []byte{0x35, 0xca}
	for i := 0; i < len(msg); i += aes.BlockSize {
		h = C1(msg[i:i+aes.BlockSize], h)
	}
	return h
}

func findCollision(state []byte) ([]byte, []byte, []byte, int) {
	found := map[[2]byte][]byte{}
	h := [2]byte{}
	cost := 0
	for {
		msg := make([]byte, aes.BlockSize)
		_, err := rand.Read(msg)
		utils.PanicOnErr(err)
		h1 := C1(msg, state)
		cost++
		copy(h[:], h1)
		if v, ok := found[h]; ok {
			if !bytes.Equal(v, msg) {
				return v, msg, h1, cost
			} else {
				// It's more likely we have a logic bug than a collision between two 128-bit messages
				panic("something is wrong")
			}
		}
		found[h] = msg
	}
}

type pair struct {
	left  []byte
	right []byte
}

type multiCollisions struct {
	pairs     []pair
	state     []byte
	totalCost int
}

func (mc *multiCollisions) increase() {
	left, right, hash, cost := findCollision(mc.state)
	mc.pairs = append(mc.pairs, pair{left: left, right: right})
	mc.totalCost += cost
	mc.state = hash
}

func (mc *multiCollisions) combine() [][]byte {
	msgs := [][]byte{{}}
	for i := 0; i < len(mc.pairs); i++ {
		// double msgs
		n := len(msgs)
		for j := 0; j < n; j++ {
			t := make([]byte, len(msgs[j]))
			copy(t, msgs[j])
			msgs = append(msgs, t)
		}
		// append left
		for j := 0; j < n; j++ {
			msgs[j] = append(msgs[j], mc.pairs[i].left...)
		}
		// append right
		for j := n; j < 2*n; j++ {
			msgs[j] = append(msgs[j], mc.pairs[i].right...)
		}
	}
	return msgs
}

func findMultiCollisions(n int) ([][]byte, int) {
	// find n pairs
	mc := &multiCollisions{
		pairs:     []pair{},
		state:     []byte{0x35, 0xca},
		totalCost: 0,
	}
	for i := 0; i < n; i++ {
		mc.increase()
	}
	return mc.combine(), mc.totalCost
}

func C2(buf []byte, key []byte) []byte {
	aesKey := []byte{}
	aesKey = append(aesKey, key...)
	aesKey = pkcs7.Pad(aesKey, 16)
	aesCipher := aes.NewAes(aesKey)
	r := make([]byte, aes.BlockSize)
	aesCipher.Encrypt(r, buf)
	return r[0:3]
}

func MD2(msg []byte) []byte {
	msg = pkcs7.Pad(msg, aes.BlockSize)
	h := []byte{0x35, 0xca, 0xe7}
	for i := 0; i < len(msg); i += aes.BlockSize {
		h = C2(msg[i:i+aes.BlockSize], h)
	}
	return h
}

func findPairCollision() ([]byte, []byte, int, int) {
	mc := &multiCollisions{
		pairs:     []pair{},
		state:     []byte{0x35, 0xca},
		totalCost: 0,
	}
	for {
		mc.increase()
		msgs := mc.combine()
		left, right, ok, cost2 := checkCollisions(msgs)
		if ok {
			return left, right, mc.totalCost, cost2
		}
	}
}

func checkCollisions(msgs [][]byte) ([]byte, []byte, bool, int) {
	m := map[[3]byte][]byte{}
	cost := 0
	for i := 0; i < len(msgs); i++ {
		h := MD2(msgs[i])
		h2 := [3]byte{}
		copy(h2[:], h)
		cost++
		if v, ok := m[h2]; ok {
			return v, msgs[i], true, cost
		}
		m[h2] = msgs[i]
	}
	return nil, nil, false, 0
}

package set7

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/encoding/pkcs7"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type expandableMessage struct {
	k           int
	piecesLeft  [][]byte
	piecesRight [][]byte
	finalHash   []byte
	cost        int
}

func Challenge53() {
	utils.PrintTitle(7, 53)

	// Create a long, random, message
	msg := make([]byte, 5000)
	_, err := rand.Read(msg)
	utils.PanicOnErr(err)
	msgHash := MD1(msg)
	fmt.Printf("msg hash: %s\n", hex.FromByteSlice(msgHash))

	// Initialize the expandable message.
	em := initExpandableMessage(len(msg))

	// sanity check by building two prefixes
	prefixLefts := []byte{}
	prefixRights := []byte{}
	for i := 0; i < em.k; i++ {
		prefixLefts = append(prefixLefts, em.piecesLeft[i]...)
		prefixRights = append(prefixRights, em.piecesRight[i]...)
	}
	prefixLeftsHash := MD1noPadding(prefixLefts, []byte{0x35, 0xca})
	prefixRightsHash := MD1noPadding(prefixRights, []byte{0x35, 0xca})
	if !bytes.Equal(prefixLeftsHash, prefixRightsHash) {
		panic("initExpandableMessage is broken")
	}

	// Find a bridge block
	bridge, offset := em.bridge(msg)

	// Build prefix
	prefix := em.prefix(offset)

	// Some sanity checks
	if len(prefix) != offset*aes.BlockSize {
		panic(fmt.Errorf("incorrect prefix length: %d != %d", len(prefix), offset*aes.BlockSize))
	}
	prefixHash := MD1noPadding(prefix, []byte{0x35, 0xca})
	if !bytes.Equal(em.finalHash, prefixHash) {
		panic(fmt.Errorf("incorrect prefix hash: %02x != %02x", em.finalHash, prefixHash))
	}

	// Combine everything
	msg2 := []byte{}
	msg2 = append(msg2, prefix...)
	msg2 = append(msg2, bridge...)
	msg2 = append(msg2, msg[(offset+1)*aes.BlockSize:]...)
	msg2Hash := MD1(msg2)
	fmt.Printf("msg2 hash: %s\n", hex.FromByteSlice(msg2Hash))
	fmt.Printf("cost: %d\n", em.cost)

	if bytes.Equal(msg, msg2) {
		panic("something is wrong")
	}
	if !bytes.Equal(msgHash, msg2Hash) {
		panic("failed")
	}

	fmt.Println()
}

func MD1noPadding(msg []byte, state []byte) []byte {
	for i := 0; i < len(msg); i += aes.BlockSize {
		state = C1(msg[i:i+aes.BlockSize], state)
	}
	return state
}

func initExpandableMessage(msgLen int) expandableMessage {
	r := expandableMessage{}

	// k is the log2(msgLen/blocksize), which is also MSB(msgLen)
	msgLen = msgLen / 16
	i := 0
	for msgLen > 1 {
		i++
		msgLen = msgLen >> 1
	}
	r.k = i

	hashState := []byte{0x35, 0xca}
	nextHashState := make([]byte, 2)
	for i := 0; i < r.k; i++ {
		// create an array of length 2^(k-1-i)+1
		copy(nextHashState, hashState)
		blocks := 1 << (r.k - 1 - i)
		piece := make([]byte, (blocks+1)*aes.BlockSize)
		nextHashState = MD1noPadding(piece[0:blocks*aes.BlockSize], nextHashState)
		r.cost += blocks

		// find a collision with hashState as initial hash state
		var left, right []byte
		var cost int
		left, right, hashState, cost = findCollision2(nextHashState, hashState)
		r.cost += cost

		copy(piece[blocks*aes.BlockSize:], left)
		r.piecesLeft = append(r.piecesLeft, piece)
		r.piecesRight = append(r.piecesRight, right)
	}
	r.finalHash = hashState
	return r
}

func (em *expandableMessage) bridge(msg []byte) ([]byte, int) {
	// compute the hash state for every part of msg
	hashes := map[[2]byte]int{}

	msg = pkcs7.Pad(msg, aes.BlockSize)
	h := []byte{0x35, 0xca}
	for i := 0; i < len(msg); i += aes.BlockSize {
		h = C1(msg[i:i+aes.BlockSize], h[:])
		em.cost++
		t := [2]byte{h[0], h[1]}
		hashes[t] = i
	}

	bridge := make([]byte, aes.BlockSize)
	for {
		_, err := rand.Read(bridge)
		utils.PanicOnErr(err)
		h := C1(bridge, em.finalHash)
		em.cost++
		t := [2]byte{h[0], h[1]}
		if v, ok := hashes[t]; ok {
			blockOffset := v / aes.BlockSize
			if blockOffset >= em.k && blockOffset <= (1<<em.k) {
				return bridge, blockOffset
			}
		}
	}
}

func (em expandableMessage) prefix(offset int) []byte {
	// to pick which pieces we need, we look at the binary representation of
	// offset - k
	t := offset - em.k
	r := []byte{}
	for i := 0; i < em.k; i++ {
		if (t>>(em.k-i-1))&1 == 1 {
			r = append(r, em.piecesLeft[i]...)
		} else {
			r = append(r, em.piecesRight[i]...)
		}
	}
	return r
}

func findCollision2(leftState []byte, rightState []byte) ([]byte, []byte, []byte, int) {
	foundLeft := map[[2]byte][]byte{}
	foundRight := map[[2]byte][]byte{}
	h := [2]byte{}
	cost := 0
	for {
		msgLeft := make([]byte, aes.BlockSize)
		_, err := rand.Read(msgLeft)
		utils.PanicOnErr(err)
		h1 := C1(msgLeft, leftState)
		cost++
		copy(h[:], h1)
		if v, ok := foundRight[h]; ok {
			if !bytes.Equal(v, msgLeft) {
				return msgLeft, v, h1, cost
			} else {
				// It's more likely we have a logic bug than a collision between two 128-bit messages
				panic("something is wrong")
			}
		}
		foundLeft[h] = msgLeft

		msgRight := make([]byte, aes.BlockSize)
		_, err = rand.Read(msgRight)
		utils.PanicOnErr(err)
		h2 := C1(msgRight, rightState)
		cost++
		copy(h[:], h2)
		if v, ok := foundLeft[h]; ok {
			if !bytes.Equal(v, msgRight) {
				return v, msgRight, h2, cost
			} else {
				// It's more likely we have a logic bug than a collision between two 128-bit messages
				panic("something is wrong")
			}
		}
		foundRight[h] = msgRight
	}
}

package set7

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

type nostradamus struct {
	k     int
	nodes []*node
	final *node
	cost  int
}

type node struct {
	hashInitialState []byte
	data             []byte
	parent           *node
}

func Challenge54() {
	utils.PrintTitle(7, 54)

	// Create random hash states
	n := newNostradamus(5)

	// Hash the padding
	padding := []byte{}
	for i := 0; i < aes.BlockSize; i++ {
		padding = append(padding, byte(aes.BlockSize))
	}
	prediction := C1(padding, n.final.hashInitialState)
	fmt.Printf("prediction hash: %02x\n", prediction)

	// Craft a message
	msg := []byte("Penguins will win the tournament")
	hashState := MD1noPadding(msg, []byte{0x35, 0xca})
	bridge, node := n.findCollision(hashState)
	msg = append(msg, bridge...)
	for node.parent != nil {
		msg = append(msg, node.data...)
		node = node.parent
	}
	fmt.Printf("message: %#v\n", string(msg))
	msgHash := MD1(msg)
	fmt.Printf("message hash: %02x\n", msgHash)
	fmt.Printf("cost: %d\n", n.cost)
	if !bytes.Equal(prediction, msgHash) {
		panic("fail")
	}

	fmt.Println()
}

func newNostradamus(k int) *nostradamus {
	r := &nostradamus{
		k: k,
	}
	n := 1 << k
	for i := 0; i < n; i++ {
		newNode := &node{
			hashInitialState: make([]byte, 2),
		}
		_, err := rand.Read(newNode.hashInitialState)
		utils.PanicOnErr(err)
		r.nodes = append(r.nodes, newNode)
	}

	reduce := r.nodes
	for len(reduce) > 1 {
		nextReduction := []*node{}
		for i := 0; i < len(reduce); i += 2 {
			left, right, hashState, cost := findCollision2(reduce[i].hashInitialState, reduce[i+1].hashInitialState)
			newNode := &node{
				hashInitialState: hashState,
			}
			r.cost += cost
			reduce[i].data = left
			reduce[i].parent = newNode
			reduce[i+1].data = right
			reduce[i+1].parent = newNode
			nextReduction = append(nextReduction, newNode)
		}
		reduce = nextReduction
	}
	r.final = reduce[0]
	return r
}

func (n *nostradamus) findCollision(hashState []byte) ([]byte, *node) {
	found := map[[2]byte]*node{}
	t := [2]byte{}
	for i := 0; i < len(n.nodes); i++ {
		node := n.nodes[i]
		copy(t[:], node.hashInitialState)
		found[t] = node
	}
	for {
		bridge := make([]byte, aes.BlockSize)
		_, err := rand.Read(bridge)
		utils.PanicOnErr(err)
		h := C1(bridge, hashState)
		copy(t[:], h)
		n.cost++
		if v, ok := found[t]; ok {
			return bridge, v
		}
	}
}

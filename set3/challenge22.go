package set3

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge22() {
	utils.PrintTitle(3, 22)

	rand.Seed(time.Now().Unix())
	seed := uint32(rand.Intn(1000))

	knownValue := NewMT(seed).next()

	for i := 0; i < 1000; i++ {
		t := NewMT(uint32(i)).next()
		if t == knownValue {
			fmt.Printf("possible seed: %d\n", i)
		}
	}
	fmt.Printf("actual seed: %d\n", seed)

	fmt.Println()
}

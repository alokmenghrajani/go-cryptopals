package set3

import (
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge22(rng *rng.Rng) {
	utils.PrintTitle(3, 22)

	seed := uint32(rng.Int(1000))
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

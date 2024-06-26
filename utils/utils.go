package utils

import (
	"fmt"
	"strings"
)

// Various functions that don't belong anywhere else.

// PrintTitle prints the set and challenge using ansi colors
func PrintTitle(set, challenge int) {
	fmt.Printf("\033[0;31mSet %d, challenge %d:\033[m\n", set, challenge)
}

// PanicOnErr panics if err is set
func PanicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

// Remaining returns the smallest non-negative x such that (n+x)%m equals 0.
func Remaining(n, m int) int {
	// note: we could optimze this function when m is a power of 2.
	t := n % m
	if t == 0 {
		return 0
	}
	return m - t
}

// Xor returns new buffer with content set to buf1 xor buf2
func Xor(buf1, buf2 []byte) []byte {
	if len(buf1) != len(buf2) {
		panic("invalid inputs")
	}
	r := []byte{}
	for i := 0; i < len(buf1); i++ {
		r = append(r, buf1[i]^buf2[i])
	}
	return r
}

// IsAdmin when given a string of the form: key1=value1;key2=value2;...
// returns true if the first "admin" key is "true".
func IsAdmin(message string) bool {
	pieces := strings.Split(message, ";")
	for _, piece := range pieces {
		tuple := strings.Split(piece, "=")
		if tuple[0] == "admin" {
			return tuple[1] == "true"
		}
	}
	return false
}

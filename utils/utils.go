package utils

import "fmt"

// print the set and challenge using ansi colors
func PrintTitle(set, challenge int) {
	fmt.Printf("\033[0;31mSet %d, challenge %d:\033[m\n", set, challenge)
}

// panic if err is set
func PanicOnErr(err error) {
	if err != nil {
		panic(err)
	}
}

// returns the smallest non-negative x such that (n+x)%m equals 0.
func Remaining(n, m int) int {
	t := n % m
	if t == 0 {
		return 0
	}
	return m - t
}

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

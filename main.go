package main

import (
	"os"

	"github.com/alokmenghrajani/go-cryptopals/set1"
	"github.com/alokmenghrajani/go-cryptopals/set2"
	"github.com/alokmenghrajani/go-cryptopals/set3"
	"github.com/alokmenghrajani/go-cryptopals/set4"
	"github.com/alokmenghrajani/go-cryptopals/set5"
	"github.com/alokmenghrajani/go-cryptopals/set6"
	"github.com/alokmenghrajani/go-cryptopals/set7"
)

func main() {
	challenge := ""
	if len(os.Args) >= 2 {
		challenge = os.Args[1]
	}
	switch challenge {
	// Set 1: Basics
	case "1":
		set1.Challenge1()
	case "2":
		set1.Challenge2()
	case "3":
		set1.Challenge3()
	case "4":
		set1.Challenge4()
	case "5":
		set1.Challenge5()
	case "6":
		set1.Challenge6()
	case "7":
		set1.Challenge7()
	case "8":
		set1.Challenge8()

	// Set 2: Block crypto
	case "9":
		set2.Challenge9()
	case "10":
		set2.Challenge10()
	case "11":
		set2.Challenge11()
	case "12":
		set2.Challenge12()
	case "13":
		set2.Challenge13()
	case "14":
		set2.Challenge14()
	case "15":
		set2.Challenge15()
	case "16":
		set2.Challenge16()

	// Set 3: Block & stream crypto
	case "17":
		set3.Challenge17()
	case "18":
		set3.Challenge18()
	case "19":
		set3.Challenge19()
	case "20":
		set3.Challenge20()
	case "21":
		set3.Challenge21()
	case "22":
		set3.Challenge22()
	case "23":
		set3.Challenge23()
	case "24":
		set3.Challenge24()

	// Set 4: Stream crypto and randomness
	case "25":
		set4.Challenge25()
	case "26":
		set4.Challenge26()
	case "27":
		set4.Challenge27()
	case "28":
		set4.Challenge28()
	case "29":
		set4.Challenge29()
	case "30":
		set4.Challenge30()
	case "31":
		set4.Challenge31()
	case "32":
		set4.Challenge32()

	// Set 5: Diffie-Hellman and friends
	case "33":
		set5.Challenge33()
	case "34":
		set5.Challenge34()
	case "35":
		set5.Challenge35()
	case "36":
		set5.Challenge36()
	case "37":
		set5.Challenge37()
	case "38":
		set5.Challenge38()
	case "39":
		set5.Challenge39()
	case "40":
		set5.Challenge40()

	// Set 6: RSA and DSA
	case "41":
		set6.Challenge41()
	case "42":
		set6.Challenge42()
	case "43":
		set6.Challenge43()
	case "44":
		set6.Challenge44()
	case "45":
		set6.Challenge45()
	case "46":
		set6.Challenge46()

	// Set 7: Hashes
	case "49":
		set7.Challenge49()
	case "50":
		set7.Challenge50()
	case "51":
		set7.Challenge51()
	case "52":
		set7.Challenge52()
	case "55":
		set7.Challenge55()
	case "56":
		set7.Challenge56()

	default:
		set7.Challenge56()
	}
}

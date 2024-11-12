package main

import (
	"os"

	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/set1"
	"github.com/alokmenghrajani/go-cryptopals/set2"
	"github.com/alokmenghrajani/go-cryptopals/set3"
	"github.com/alokmenghrajani/go-cryptopals/set4"
	"github.com/alokmenghrajani/go-cryptopals/set5"
	"github.com/alokmenghrajani/go-cryptopals/set6"
	"github.com/alokmenghrajani/go-cryptopals/set7"
	"github.com/alokmenghrajani/go-cryptopals/set8"
)

func main() {
	rng := rng.New()

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
		set2.Challenge11(rng)
	case "12":
		set2.Challenge12(rng)
	case "13":
		set2.Challenge13(rng)
	case "14":
		set2.Challenge14(rng)
	case "15":
		set2.Challenge15()
	case "16":
		set2.Challenge16(rng)

	// Set 3: Block & stream crypto
	case "17":
		set3.Challenge17(rng)
	case "18":
		set3.Challenge18()
	case "19":
		set3.Challenge19(rng)
	case "20":
		set3.Challenge20(rng)
	case "21":
		set3.Challenge21()
	case "22":
		set3.Challenge22(rng)
	case "23":
		set3.Challenge23(rng)
	case "24":
		set3.Challenge24(rng)

	// Set 4: Stream crypto and randomness
	case "25":
		set4.Challenge25(rng)
	case "26":
		set4.Challenge26(rng)
	case "27":
		set4.Challenge27(rng)
	case "28":
		set4.Challenge28()
	case "29":
		set4.Challenge29(rng)
	case "30":
		set4.Challenge30(rng)
	case "31":
		set4.Challenge31(rng)
	case "32":
		set4.Challenge32(rng)

	// Set 5: Diffie-Hellman and friends
	case "33":
		set5.Challenge33(rng)
	case "34":
		set5.Challenge34(rng)
	case "35":
		set5.Challenge35(rng)
	case "36":
		set5.Challenge36(rng)
	case "37":
		set5.Challenge37(rng)
	case "38":
		set5.Challenge38(rng)
	case "39":
		set5.Challenge39(rng)
	case "40":
		set5.Challenge40(rng)

	// Set 6: RSA and DSA
	case "41":
		set6.Challenge41(rng)
	case "42":
		set6.Challenge42()
	case "43":
		set6.Challenge43(rng)
	case "44":
		set6.Challenge44(rng)
	case "45":
		set6.Challenge45(rng)
	case "46":
		set6.Challenge46(rng)
	case "47":
		set6.Challenge47(rng)
	case "48":
		set6.Challenge48(rng)

	// Set 7: Hashes
	case "49":
		set7.Challenge49(rng)
	case "50":
		set7.Challenge50()
	case "51":
		set7.Challenge51(rng)
	case "52":
		set7.Challenge52(rng)
	case "53":
		set7.Challenge53(rng)
	case "54":
		set7.Challenge54(rng)
	case "55":
		set7.Challenge55(rng)
	case "56":
		set7.Challenge56(rng)

	// Set 8: Abstract Algebra
	case "57":
		set8.Challenge57(rng)

	default:
		set8.Challenge57(rng)
	}
}

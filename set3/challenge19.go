package set3

import (
	"crypto/rand"
	"fmt"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge19() {
	utils.PrintTitle(3, 19)

	ciphertexts := getCiphertexts()

	// calculate longest ciphertext
	max := 0
	for _, ciphertext := range ciphertexts {
		if len(ciphertext) > max {
			max = len(ciphertext)
		}
	}

	// for each keystream byte, find the value which results in the most ascii values
	// this works fine for the first few bytes, but since the number of ciphertexts drops
	// as the value of i increases, the accuracy of this method decreases.
	// It's however quite easy to fix each sentence by hand.
	keyStream := []byte{}
	for i := 0; i < max; i++ {
		bestScore := -1
		bestValue := byte(0)
		for j := 0; j < 256; j++ {
			score := 0
			for _, ciphertext := range ciphertexts {
				if i >= len(ciphertext) {
					continue
				}
				t := ciphertext[i] ^ byte(j)
				if t >= 'a' && t <= 'z' {
					score++
				} else if t >= 'A' && t <= 'Z' {
					score++
				} else if t == ' ' {
					score++
				}
			}
			if score > bestScore {
				bestScore = score
				bestValue = byte(j)
			}
		}
		keyStream = append(keyStream, bestValue)
	}

	for _, ciphertext := range ciphertexts {
		plaintext := []byte{}
		for i := 0; i < len(ciphertext); i++ {
			plaintext = append(plaintext, ciphertext[i]^keyStream[i])
		}
		fmt.Println(string(plaintext))
	}

	fmt.Println()
}

func getCiphertexts() [][]byte {
	ciphertexts := [][]byte{}
	plaintexts := []string{
		"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
		"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
		"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
		"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
		"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
		"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
		"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
		"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
		"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
		"VG8gcGxlYXNlIGEgY29tcGFuaW9u",
		"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
		"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
		"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
		"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
		"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
		"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
		"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
		"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
		"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
		"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
		"U2hlIHJvZGUgdG8gaGFycmllcnM/",
		"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
		"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
		"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
		"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
		"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
		"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
		"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
		"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
		"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
		"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
		"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
		"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
		"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
		"SW4gdGhlIGNhc3VhbCBjb21lZHk7",
		"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
		"VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
		"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
	}
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)
	for _, plaintext := range plaintexts {
		aesCtr := NewAesCtr(aesKey, 0)
		ciphertexts = append(ciphertexts, aesCtr.process(utils.Base64ToByteSlice(plaintext)))
	}
	return ciphertexts
}

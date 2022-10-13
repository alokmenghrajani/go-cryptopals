package set7

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"fmt"
	"math"
	insecureRand "math/rand"

	"github.com/alokmenghrajani/go-cryptopals/utils"
	"github.com/alokmenghrajani/go-cryptopals/utils/aes"
)

func Challenge51() {
	utils.PrintTitle(7, 51)

	fmt.Println("part 1: stream cipher")
	session := crackStreamCipher()
	fmt.Printf("secret: %s\n", session)
	if session == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=" {
		fmt.Println("success!")
	} else {
		panic("failed to crack session")
	}
	fmt.Println()

	fmt.Println("part 2: block cipher")
	session = crackBlockCipher()
	fmt.Printf("secret: %s\n", session)
	if session == "sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=" {
		fmt.Println("success!")
	} else {
		panic("failed to crack session")
	}
	fmt.Println()
}

func crackStreamCipher() string {
	// We'll use the knowledge that the session has the format:
	// "sessionid=" + base64(32 bytes)
	candidates := []string{"sessionid="}

	for i := 0; i < 43; i++ {
		candidates = findNextStreamCipherCandidates(candidates)
	}
	if len(candidates) > 1 {
		panic("found more than 1 candidate")
	}
	candidate := candidates[0] + "="

	return candidate
}

func findNextStreamCipherCandidates(candidates []string) []string {
	bestScore := math.MaxInt
	best := []string{}

	base64 := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")

	for _, candidate := range candidates {
		newCandidate := make([]byte, len(candidate)+1)
		copy(newCandidate, []byte(candidate))
		for i := 0; i < 64; i++ {
			newCandidate[len(candidate)] = base64[i]
			score := streamCipherOracle(newCandidate)
			if score < bestScore {
				bestScore = score
				best = []string{string(newCandidate)}
			} else if score == bestScore {
				best = append(best, string(newCandidate))
			}
		}
	}

	return best
}

func streamCipherOracle(d []byte) int {
	return len(encryptAesCtr(compress(formatRequest(d))))
}

func crackBlockCipher() string {
	// We'll use the knowledge that the session has the format:
	// "sessionid=" + base64(32 bytes)
	candidates := []string{"sessionid="}

	for i := 0; i < 43; i++ {
		candidates = findNextBlockCipherCandidates(candidates)
	}
	if len(candidates) > 1 {
		panic("found more than 1 candidate")
	}
	candidate := candidates[0] + "="

	return candidate
}

func findNextBlockCipherCandidates(candidates []string) []string {
	base64 := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/")

	// We keep increasing the prefix until we hit a block boundary. Only then can we distinguish which
	// bytes compresses better.
	prefix := make([]byte, 0, 16)
	for {
		bestScore := math.MaxInt
		best := []string{}

		for _, candidate := range candidates {
			newCandidate := make([]byte, len(prefix)+len(candidate)+1)
			copy(newCandidate, prefix)
			copy(newCandidate[len(prefix):], []byte(candidate))
			for i := 0; i < 64; i++ {
				newCandidate[len(prefix)+len(candidate)] = base64[i]
				score := blockCipherOracle(newCandidate)
				if score < bestScore {
					bestScore = score
					best = []string{string(newCandidate[len(prefix):])}
				} else if score == bestScore {
					best = append(best, string(newCandidate[len(prefix):]))
				}
			}
		}

		if len(best) != 64 {
			return best
		}

		prefix = append(prefix, byte(len(prefix)))
		if len(prefix) > 100 {
			// something is broken if we haven't found anything at this point. We can't stop
			// when the prefix is exactly 16 bytes because the prefix itself might be getting
			// compressed.
			panic("failed to find best byte")
		}
	}
}

func blockCipherOracle(d []byte) int {
	return len(encryptAesCbc(compress(formatRequest(d))))
}

func formatRequest(p []byte) []byte {
	r := []byte(fmt.Sprintf(`POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: %d
`, len(p)))
	r = append(r, p...)
	return r
}

func compress(d []byte) []byte {
	var buf bytes.Buffer

	zw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	utils.PanicOnErr(err)

	_, err = zw.Write(d)
	utils.PanicOnErr(err)

	err = zw.Close()
	utils.PanicOnErr(err)

	return buf.Bytes()
}

func encryptAesCtr(plaintext []byte) []byte {
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	nonce := insecureRand.Uint64()

	aesCtr := aes.NewAesCtr(aesKey, nonce)
	return aesCtr.Process(plaintext)
}

func encryptAesCbc(plaintext []byte) []byte {
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	utils.PanicOnErr(err)

	paddedPlaintext := utils.Pad(plaintext, 16)
	return aes.AesCbcEncrypt(paddedPlaintext, aesKey, iv)
}

package set4

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/cryptography/aes"
	"github.com/alokmenghrajani/go-cryptopals/cryptography/hmacSha1"
	"github.com/alokmenghrajani/go-cryptopals/encoding/hex"
	"github.com/alokmenghrajani/go-cryptopals/rng"
	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge31(rng *rng.Rng) {
	utils.PrintTitle(4, 31)

	// Generate random key
	key := rng.Bytes(aes.KeySize)

	fmt.Printf("expected signature:\n% x\n", hmacSha1.Compute(key, []byte("foo"))[0:5])

	// Use httptest as it makes some things simpler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file != "foo" {
			w.WriteHeader(404)
			return
		}
		expectedSig := hmacSha1.Compute(key, []byte(file))
		// truncate expectedSig to speed things up
		expectedSig = expectedSig[0:5]

		sig := hex.ToByteSlice(r.URL.Query().Get("signature"))
		if !slowCompare(expectedSig, sig, 50*time.Millisecond) {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// use timing information to bruteforce the signature
	client := ts.Client()
	u, err := url.Parse(ts.URL)
	utils.PanicOnErr(err)
	query := u.Query()
	query.Add("file", "foo")

	sig := make([]byte, 5)
	ok := false
outer:
	for i := 0; i < len(sig); i++ {
		bestTime := 0 * time.Second
		bestValue := 0
		for b := 0; b < 256; b++ {
			sig[i] = byte(b)
			query.Set("signature", hex.FromByteSlice(sig))
			u.RawQuery = query.Encode()
			start := time.Now()
			res, err := client.Get(u.String())
			utils.PanicOnErr(err)
			if res.StatusCode == 200 {
				fmt.Printf("%02x ", b)
				ok = true
				break outer
			}
			d := time.Since(start)
			if d > bestTime {
				bestTime = d
				bestValue = b
			}
		}
		sig[i] = byte(bestValue)
		fmt.Printf("%02x ", bestValue)
	}
	fmt.Println()

	if ok {
		fmt.Println("response code: 200")
	} else {
		fmt.Println("failed")
	}

	fmt.Println()
}

func slowCompare(buf1, buf2 []byte, wait time.Duration) bool {
	if len(buf1) != len(buf2) {
		return false
	}
	for i := 0; i < len(buf1); i++ {
		if buf1[i] != buf2[i] {
			return false
		}
		time.Sleep(wait)
	}
	return true
}

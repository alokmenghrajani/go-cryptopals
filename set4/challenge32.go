package set4

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge32() {
	utils.PrintTitle(4, 32)

	// Generate random key
	key := make([]byte, 16)
	_, err := rand.Read(key)
	utils.PanicOnErr(err)

	fmt.Printf("expected signature:\n% x\n", utils.HmacSha1(key, []byte("foo"))[0:5])

	// Use httptest as it makes some things simpler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if file != "foo" {
			w.WriteHeader(404)
			return
		}
		expectedSig := utils.HmacSha1(key, []byte(file))
		// truncate expectedSig to speed things up
		expectedSig = expectedSig[0:5]

		sig := utils.HexToByteSlice(r.URL.Query().Get("signature"))
		if !slowCompare(expectedSig, sig, 5*time.Millisecond) {
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
			query.Set("signature", utils.ByteSliceToHex(sig))
			u.RawQuery = query.Encode()
			start := time.Now()
			// Iterating 4x is much simpler than doing complicated math... A bit of statistical
			// analysis would enable us to lower the wait in slowCompare
			for j := 0; j < 4; j++ {
				res, err := client.Get(u.String())
				utils.PanicOnErr(err)
				if res.StatusCode == 200 {
					fmt.Printf("%02x ", b)
					ok = true
					break outer
				}
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

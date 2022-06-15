package set2

import (
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/alokmenghrajani/go-cryptopals/utils"
)

func Challenge13() {
	utils.PrintTitle(2, 13)

	// generate a global key
	aesKey := make([]byte, 16)
	_, err := rand.Read(aesKey)
	utils.PanicOnErr(err)

	// craft an admin profile
	t := craftAdminProfile(aesKey)
	fmt.Printf("role: %s\n", role(t, aesKey))

	fmt.Println()
}

func parseString(input string) map[string]string {
	r := map[string]string{}
	pieces := strings.Split(input, "&")
	for _, v := range pieces {
		kv := strings.SplitN(v, "=", 2)
		r[kv[0]] = kv[1]
	}
	return r
}

func encode(data map[string]string) string {
	// to keep things simple, let's make the encoding process stable
	order := []string{"email", "uid", "role"}
	r := []string{}
	for _, k := range order {
		v := data[k]
		v = strings.ReplaceAll(v, "&", "_")
		v = strings.ReplaceAll(v, "=", "_")
		r = append(r, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(r, "&")
}

func profileFor(email string, aesKey []byte) []byte {
	profile := map[string]string{
		"email": email,
		"uid":   "10",
		"role":  "user",
	}
	data := encode(profile)
	return aesEcbEncrypt(Pad([]byte(data), 16), aesKey)
}

func role(ciphertext, aesKey []byte) string {
	data := aesEcbDecrypt(ciphertext, aesKey)
	data, err := Unpad(data, 16)
	utils.PanicOnErr(err)
	profile := parseString(string(data))
	return profile["role"]
}

func aesEcbDecrypt(buf, key []byte) []byte {
	cipher := utils.NewAes(key)
	output := []byte{}
	t := make([]byte, 16)
	for i := 0; i < len(buf); i += 16 {
		cipher.Decrypt(t, buf[i:i+16])
		output = append(output, t...)
	}
	return output
}

func craftAdminProfile(aesKey []byte) []byte {
	// we can produce the ciphertext for:
	// email=<our-string>&uid=10&role=user
	//
	// and we want to produce:
	// email=<our-string>&uid=10&role=admin
	//
	// step 1. create a block which just contains "admin<padding>" and encrypt it.
	// step 2. get "user" to land on the final block.
	// step 3. overwrite step2's last block with the ciphertext for the admin block.

	len1 := len("email=")
	l := utils.Remaining(len1, 16)
	string1 := strings.Repeat("x", l)
	string1 += string(Pad([]byte("admin"), 16))
	ciphertext1 := profileFor(string1, aesKey)

	len2 := len("email=&uid=10&role=")
	l = utils.Remaining(len2, 16)
	string2 := strings.Repeat("x", l)
	ciphertext2 := profileFor(string2, aesKey)

	// copy 2nd block of ciphertext1 into ciphertext2's last block
	copy(ciphertext2[len(ciphertext2)-16:], ciphertext1[16:32])
	return ciphertext2
}

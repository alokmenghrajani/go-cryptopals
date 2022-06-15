# go-cryptopals
Solutions to the [cryptopals crypto challenges](https://cryptopals.com/) 🔒 in well commented Golang.

Everything is implemented from scratch (hex, base64, AES, SHA1) for lolz.

## Set 1
- [Convert hex to base64](set1/challenge1.go)
- [Fixed XOR](set1/challenge2.go)
- [Single-byte XOR cipher](set1/challenge3.go)
- [Detect single-character XOR](set1/challenge4.go)
- [Implement repeating-key XOR](set1/challenge5.go)
- [Break repeating-key XOR](set1/challenge6.go)
- [AES in ECB mode](set1/challenge7.go)
- [Detect AES in ECB mode](set1/challenge8.go)

## Set 2
- [Implement PKCS#7 padding](set2/challenge9.go)
- [Implement CBC mode](set2/challenge10.go)
- [An ECB/CBC detection oracle](set2/challenge11.go)
- [Byte-at-a-time ECB decryption (Simple)](set2/challenge12.go)
- [ECB cut-and-paste](set2/challenge13.go)
- [Byte-at-a-time ECB decryption (Harder)](set2/challenge14.go)
- [PKCS#7 padding validation](set2/challenge15.go)
- [CBC bitflipping attacks](set2/challenge16.go)

## Set 3
- [The CBC padding oracle](set3/challenge17.go)
- [Implement CTR, the stream cipher mode](set3/challenge18.go)
- [Break fixed-nonce CTR mode using substitutions](set3/challenge19.go)
- [Break fixed-nonce CTR statistically](set3/challenge20.go)
- [Implement the MT19937 Mersenne Twister RNG](set3/challenge21.go)
- [Crack an MT19937 seed](set3/challenge22.go)
- [Clone an MT19937 RNG from its output](set3/challenge23.go)
- [Create the MT19937 stream cipher and break it](set3/challenge24.go)

## Set 4
- [Break "random access read/write" AES CTR](set4/challenge25.go)
- [CTR bitflipping](set4/challenge26.go)
- [Recover the key from CBC with IV=Key](set4/challenge27.go)

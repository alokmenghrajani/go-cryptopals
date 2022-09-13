# go-cryptopals
Solutions to the [cryptopals crypto challenges](https://cryptopals.com/) 🔒 in well<sup>[<i>[citation needed]()</i>]</sup> commented Golang.

A lot of things are implemented from scratch for lolz: hex, base64, [AES](http://www.moserware.com/assets/stick-figure-guide-to-advanced/aes_act_3_scene_02_agreement_576.png) with various modes (plain, ECB, CBC), SHA-1, SHA-256, MD4, HMAC-SHA1, HMAC-SHA256, etc.

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
- [Implement a SHA-1 keyed MAC](set4/challenge28.go)
- [Break a SHA-1 keyed MAC using length extension](set4/challenge29.go)
- [Break an MD4 keyed MAC using length extension](set4/challenge30.go)
- [Implement and break HMAC-SHA1 with an artificial timing leak](set4/challenge31.go)
- [Break HMAC-SHA1 with a slightly less artificial timing leak](set4/challenge32.go)

## Set 5
- [Implement Diffie-Hellman](set5/challenge33.go)
- [Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection](set5/challenge34.go)
- [Implement DH with negotiated groups, and break with malicious "g" parameters](set5/challenge35.go)
- [Implement Secure Remote Password (SRP)](set5/challenge36.go)
- [Break SRP with a zero key](set5/challenge37.go)
- [Offline dictionary attack on simplified SRP](set5/challenge38.go)
- [Implement RSA](set5/challenge39.go)
- [Implement an E=3 RSA Broadcast attack](set5/challenge40.go)

## Set 6
- [Implement unpadded message recovery oracle](set6/challenge41.go)
- [Bleichenbacher's e=3 RSA Attack](set6/challenge42.go)
- [DSA key recovery from nonce](set6/challenge43.go)
- [DSA nonce recovery from repeated nonce](set6/challenge44.go)
- [DSA parameter tampering](set6/challenge45.go)

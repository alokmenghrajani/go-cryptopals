# go-cryptopals
My solutions to the [Cryptopals cryptography challenges](https://cryptopals.com/) 🔒 in well<sup>[<i>[citation needed]()</i>]</sup> commented Golang.

A lot of things are implemented from scratch for lolz: [hex](encoding/hex), [base64](encoding/base64), [AES](http://www.moserware.com/assets/stick-figure-guide-to-advanced/aes_act_3_scene_02_agreement_576.png) with various [modes](cryptography/aes) (plain, ECB, CBC, CTR), [SHA-1](cryptography/sha1), [SHA-256](cryptography/sha256), [MD4](cryptography/md4), [HMAC-SHA1](cryptography/hmacSha1), [HMAC-SHA256](cryptography/hmacSha256).

A [branch](https://github.com/alokmenghrajani/go-cryptopals/tree/bigint) implements bigints from
scratch but is currently too slow to be used to solve all the challenges.

The [references](references/) folder contains a copy of various whitepapers and
RFCs useful for solving these challenges.

I have solved sets 1 through 7. I hope to finish the final set 8 soon 🤞.

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
- [RSA parity oracle](set6/challenge46.go)
- [Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)](set6/challenge47.go)
- [Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)](set6/challenge48.go)

## Set 7
- [CBC-MAC Message Forgery](set7/challenge49.go)
- [Hashing with CBC-MAC](set7/challenge50.go)
- [Compression Ratio Side-Channel Attacks](set7/challenge51.go)
- [Iterated Hash Function Multicollisions](set7/challenge52.go)
- [Kelsey and Schneier's Expandable Messages](set7/challenge53.go)
- [Kelsey and Kohno's Nostradamus Attack](set7/challenge54.go)
- [MD4 Collisions](set7/challenge55.go)
- [RC4 Single-Byte Biases](set7/challenge56.go)

## Set 8
- [Diffie-Hellman Revisited: Small Subgroup Confinement](set8/challenge57.go)
- Pollard's Method for Catching Kangaroos
- Elliptic Curve Diffie-Hellman and Invalid-Curve Attacks
- Single-Coordinate Ladders and Insecure Twists
- Duplicate-Signature Key Selection in ECDSA (and RSA)
- Key-Recovery Attacks on ECDSA with Biased Nonces
- Key-Recovery Attacks on GCM with Repeated Nonces
- Key-Recovery Attacks on GCM with a Truncated MAC
- Truncated-MAC GCM Revisited: Improving the Key-Recovery Attack via Ciphertext Length Extension
- Exploiting Implementation Errors in Diffie-Hellman

## Set 9
I found an [unofficial set 9](https://ilchen.github.io/cryptopals/newproblems.html) by Andrei Ilchenko.

package big

// ProbablyPrime checks if v1 is prime with some likelihood. Keep in mind that
// some Carmichael numbers trigger a false positive (the function will return true for
// composite numbers). Producing Carmichael numbers is trivial since there's a
// formula for it.
//
// There exists many ways to probabilistically check if a number is prime. Some of these
// methods even have no known false positives! Most methods are however quite complicated
// to implement. Some methods are based on conjecture while others aren't -- the whole area
// is quite fascinating!
//
// For the purpose of Cryptopals, I could just always return true and all the challenges
// will work fine -- but where is the fun in doing that?
//
// There also exists ways to generate primes which are guaranteed to be prime (i.e.
// generate a primality certificate at the same time).
//
// To keep things simple, this code first rules multiples of the first few primes. It then
// performs 4 rounds of Fermat's check. This is similar to how PGP in the 1990s worked.
//
// Some links to learn more about prime numbers:
// - https://en.wikipedia.org/wiki/Carmichael_number
// - https://en.wikipedia.org/wiki/Strong_prime
// - https://en.wikipedia.org/wiki/Strong_pseudoprime
// - https://en.wikipedia.org/wiki/Safe_and_Sophie_Germain_primes
// - https://en.wikipedia.org/wiki/Lucas_pseudoprime
// - https://en.wikipedia.org/wiki/Blum_integer
//
// And links to learn about primality tests:
// - https://en.wikipedia.org/wiki/Primality_certificate
// - https://en.wikipedia.org/wiki/Fermat_primality_test
// - https://github.com/embecosm/mibench/blob/master/security/pgp/src/genprime.c#L317
// - https://en.wikipedia.org/wiki/Miller%E2%80%93Rabin_primality_test
// - https://en.wikipedia.org/wiki/Baillie%E2%80%93PSW_primality_test
// - https://en.wikipedia.org/wiki/AKS_primality_test
// - https://en.wikipedia.org/wiki/Elliptic_curve_primality
// - https://en.wikipedia.org/wiki/Adleman%E2%80%93Pomerance%E2%80%93Rumely_primality_test
// - https://en.wikipedia.org/wiki/Pocklington_primality_test
// - https://en.wikipedia.org/wiki/Solovay%E2%80%93Strassen_primality_test
func (v1 *Int) ProbablyPrime() bool {
	if v1.Cmp(Zero) != 1 {
		panic("bad input")
	}

	// Check if v1 is among the first 4 primes. Typical implementations check more values,
	// since these checks are quick. Some libraries even have a neat optimization: they
	// first compute a modulo with a large number (which is the product of many small primes)
	// and then perform a standard modulo for each of the small primes.
	// See https://github.com/golang/go/blob/master/src/math/big/prime.go#L57
	smallPrimes := []int64{2, 3, 5, 7}
	for _, v := range smallPrimes {
		t := v1.Cmp(NewInt(v))
		if t == 0 {
			return true
		}
		if t == -1 {
			return false
		}
	}

	if v1.v[0]&1 == 0 {
		// Multiples of 2 aren't prime. This simple check gives us a 2x speedup.
		return false
	}

	// Perform 4 rounds of Fermat primality test
	pminus1 := v1.Sub(One)
	i := 0
	for i < 4 {
		// a can be any random number in the (1, p-1) range.
		a := NewInt(smallPrimes[i])
		r := a.ExpMod(pminus1, v1)
		if r.Cmp(One) != 0 {
			return false
		}
		i++
	}
	return true
}

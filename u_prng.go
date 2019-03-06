/*
 * Copyright (c) 2019, Psiphon Inc.
 * All rights reserved.
 *
 * Released under utls licence:
 * https://github.com/refraction-networking/utls/blob/master/LICENSE
 */

// This code is a pared down version of:
// https://github.com/Psiphon-Labs/psiphon-tunnel-core/blob/158caea562287284cc3fa5fcd1b3c97b1addf659/psiphon/common/prng/prng.go

package tls

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"math"
	"math/rand"
	"sync"

	"github.com/Yawning/chacha20"
)

const (
	PRNGSeedLength = 32
)

// PRNGSeed is a PRNG seed.
type PRNGSeed [PRNGSeedLength]byte

// NewPRNGSeed creates a new PRNG seed using crypto/rand.Read.
func NewPRNGSeed() (*PRNGSeed, error) {
	seed := new(PRNGSeed)
	_, err := crypto_rand.Read(seed[:])
	if err != nil {
		return nil, err
	}
	return seed, nil
}

// prng is a seeded, unbiased PRNG based on chacha20. that is suitable for use
// cases such as obfuscation.
//
// Seeding is based on crypto/rand.Read and the PRNG stream is provided by
// chacha20.
//
// This PRNG is _not_ for security use cases including production cryptographic
// key generation.
//
// Limitations: there is a cycle in the PRNG stream, after roughly 2^64 * 2^38-64
// bytes.
//
// It is safe to make concurrent calls to a PRNG instance.
//
// PRNG conforms to io.Reader and math/rand.Source, with additional helper
// functions.
type prng struct {
	rand                   *rand.Rand
	randomStreamMutex      sync.Mutex
	randomStreamSeed       *PRNGSeed
	randomStream           *chacha20.Cipher
	randomStreamUsed       uint64
	randomStreamRekeyCount uint64
}

// newPRNG generates a seed and creates a PRNG with that seed.
func newPRNG() (*prng, error) {
	seed, err := NewPRNGSeed()
	if err != nil {
		return nil, err
	}
	return newPRNGWithSeed(seed), nil
}

// newPRNGWithSeed initializes a new PRNG using an existing seed.
func newPRNGWithSeed(seed *PRNGSeed) *prng {
	p := &prng{
		randomStreamSeed: seed,
	}
	p.rekey()
	p.rand = rand.New(p)
	return p
}

// Read reads random bytes from the PRNG stream into b. Read conforms to
// io.Reader and always returns len(p), nil.
func (p *prng) Read(b []byte) (int, error) {

	p.randomStreamMutex.Lock()
	defer p.randomStreamMutex.Unlock()

	// Re-key before reaching the 2^38-64 chacha20 key stream limit.
	if p.randomStreamUsed+uint64(len(b)) >= uint64(1<<38-64) {
		p.rekey()
	}

	p.randomStream.KeyStream(b)

	p.randomStreamUsed += uint64(len(b))

	return len(b), nil
}

func (p *prng) rekey() {

	// chacha20 has a stream limit of 2^38-64. Before that limit is reached,
	// the cipher must be rekeyed. To rekey without changing the seed, we use
	// a counter for the nonce.
	//
	// Limitation: the counter wraps at 2^64, which produces a cycle in the
	// PRNG after 2^64 * 2^38-64 bytes.
	//
	// TODO: this could be extended by using all 2^96 bits of the nonce for
	// the counter; and even further by using the 24 byte XChaCha20 nonce.
	var randomKeyNonce [12]byte
	binary.BigEndian.PutUint64(randomKeyNonce[0:8], p.randomStreamRekeyCount)

	var err error
	p.randomStream, err = chacha20.NewCipher(
		p.randomStreamSeed[:], randomKeyNonce[:])
	if err != nil {
		// Functions returning random values, which may call rekey, don't
		// return an error. As of github.com/Yawning/chacha20 rev. e3b1f968,
		// the only possible errors from chacha20.NewCipher invalid key or
		// nonce size, and since we use the correct sizes, there should never
		// be an error here. So panic in this unexpected case.
		panic(err)
	}

	p.randomStreamRekeyCount += 1
	p.randomStreamUsed = 0
}

// Int63 is equivilent to math/read.Int63.
func (p *prng) Int63() int64 {
	i := p.Uint64()
	return int64(i & (1<<63 - 1))
}

// Int63 is equivilent to math/read.Uint64.
func (p *prng) Uint64() uint64 {
	var b [8]byte
	p.Read(b[:])
	return binary.BigEndian.Uint64(b[:])
}

// Seed must exist in order to use a PRNG as a math/rand.Source. This call is
// not supported and ignored.
func (p *prng) Seed(_ int64) {
}

// FlipWeightedCoin returns the result of a weighted
// random coin flip. If the weight is 0.5, the outcome
// is equally likely to be true or false. If the weight
// is 1.0, the outcome is always true, and if the
// weight is 0.0, the outcome is always false.
//
// Input weights > 1.0 are treated as 1.0.
func (p *prng) FlipWeightedCoin(weight float64) bool {
	if weight > 1.0 {
		weight = 1.0
	}
	f := float64(p.Int63()) / float64(math.MaxInt64)
	return f > 1.0-weight
}

// Intn is equivilent to math/read.Intn, except it returns 0 if n <= 0
// instead of panicking.
func (p *prng) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	return p.rand.Intn(n)
}

// Int63n is equivilent to math/read.Int63n, except it returns 0 if n <= 0
// instead of panicking.
func (p *prng) Int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return p.rand.Int63n(n)
}

// Intn is equivilent to math/read.Perm.
func (p *prng) Perm(n int) []int {
	return p.rand.Perm(n)
}

// Range selects a random integer in [min, max].
// If min < 0, min is set to 0. If max < min, min is returned.
func (p *prng) Range(min, max int) int {
	if min < 0 {
		min = 0
	}
	if max < min {
		return min
	}
	n := p.Intn(max - min + 1)
	n += min
	return n
}

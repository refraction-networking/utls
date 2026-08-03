package tls

import (
	"golang.org/x/crypto/sha3"
)

func kyberSharedSecret(c, K []byte) []byte {
	// Package mlkem implements ML-KEM, which compared to Kyber removed a
	// final hashing step. Compute SHAKE-256(K || SHA3-256(c), 32) to match Kyber.
	// See https://words.filippo.io/mlkem768/#bonus-track-using-a-ml-kem-implementation-as-kyber-v3.
	h := sha3.NewShake256()
	h.Write(K)
	ch := sha3.New256()
	ch.Write(c)
	h.Write(ch.Sum(nil))
	out := make([]byte, 32)
	h.Read(out)
	return out
}

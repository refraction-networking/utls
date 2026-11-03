// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	crand "crypto/rand"
	"math/rand/v2"
)

// RandomizedWeights are the probabilities (0..1) a randomized fingerprint uses
// for its choices. DefaultWeights produces a broad, always-negotiable mix.
type RandomizedWeights struct {
	ALPN              float64 // offer ALPN h2/http1.1
	TLS13             float64 // offer TLS 1.3 (else TLS 1.2 only)
	PostQuantum       float64 // offer X25519MLKEM768 (group + key share)
	FirstShareP256    float64 // P-256 instead of X25519 as the classical key share
	CertCompression   float64 // offer brotli certificate compression
	ShuffleExtensions float64 // permute the extension order
	GREASE            float64 // use GREASE values
	Padding           float64 // add a padding extension
}

// DefaultWeights is the default distribution.
var DefaultWeights = RandomizedWeights{
	ALPN: 0.7, TLS13: 0.9, PostQuantum: 0.6, FirstShareP256: 0.25,
	CertCompression: 0.5, ShuffleExtensions: 0.8, GREASE: 0.8, Padding: 0.5,
}

var (
	// HelloRandomized draws a new random, negotiable fingerprint per connection.
	HelloRandomized = register(ClientHelloID{Client: "Randomized", Version: "Auto", kind: kindRandomized}, "randomized", "random")
	// HelloRandomizedALPN always offers ALPN.
	HelloRandomizedALPN = register(ClientHelloID{Client: "Randomized", Version: "ALPN", kind: kindRandomized, weights: &RandomizedWeights{
		ALPN: 1, TLS13: 0.9, PostQuantum: 0.6, FirstShareP256: 0.25, CertCompression: 0.5, ShuffleExtensions: 0.8, GREASE: 0.8, Padding: 0.5,
	}}, "randomizedalpn")
	// HelloRandomizedNoALPN never offers ALPN.
	HelloRandomizedNoALPN = register(ClientHelloID{Client: "Randomized", Version: "NoALPN", kind: kindRandomized, weights: &RandomizedWeights{
		ALPN: 0, TLS13: 0.9, PostQuantum: 0.6, FirstShareP256: 0.25, CertCompression: 0.5, ShuffleExtensions: 0.8, GREASE: 0.8, Padding: 0.5,
	}}, "randomizednoalpn")
)

// NewPRNGSeed returns a fresh seed for SeededRandomized.
func NewPRNGSeed() ([32]byte, error) {
	var s [32]byte
	_, err := crand.Read(s[:])
	return s, err
}

// SeededRandomized returns a randomized fingerprint that is a pure function of
// seed and weights: every connection (and every process) using the same seed
// sends the same ClientHello shape (only per-connection values such as keys,
// random, session ID and GREASE codepoints differ). weights nil means
// DefaultWeights. Use it to replay a randomized profile across connections.
func SeededRandomized(seed [32]byte, weights *RandomizedWeights) ClientHelloID {
	s := seed
	var w *RandomizedWeights
	if weights != nil {
		c := *weights
		w = &c
	}
	return ClientHelloID{Client: "Randomized", Version: "Seeded", kind: kindRandomized, seed: &s, weights: w}
}

// randomizedSpec builds a valid, negotiable spec from seed (fresh if nil).
func randomizedSpec(seed *[32]byte, w *RandomizedWeights) (*ClientHelloSpec, error) {
	var s [32]byte
	if seed != nil {
		s = *seed
	} else if _, err := crand.Read(s[:]); err != nil {
		return nil, err
	}
	if w == nil {
		w = &DefaultWeights
	}
	r := rand.New(rand.NewChaCha8(s))
	flip := func(p float64) bool { return r.Float64() < p }

	tls13 := flip(w.TLS13)
	grease := flip(w.GREASE)
	pq := tls13 && flip(w.PostQuantum)
	p256First := flip(w.FirstShareP256)

	var ciphers []uint16
	if grease {
		ciphers = append(ciphers, GREASE_PLACEHOLDER)
	}
	if tls13 {
		t13 := []uint16{TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256}
		r.Shuffle(len(t13), func(i, j int) { t13[i], t13[j] = t13[j], t13[i] })
		ciphers = append(ciphers, t13...)
	}
	legacy := []uint16{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
	}
	r.Shuffle(len(legacy)-2, func(i, j int) { legacy[i+2], legacy[j+2] = legacy[j+2], legacy[i+2] })
	ciphers = append(ciphers, legacy[:4+r.IntN(len(legacy)-3)]...) // always the two AES-GCM ECDHE suites

	groups := []CurveID{}
	if grease {
		groups = append(groups, GREASE_PLACEHOLDER)
	}
	if pq {
		groups = append(groups, X25519MLKEM768)
	}
	groups = append(groups, X25519, CurveP256, CurveP384)

	var shares []KeyShareEntry
	if grease {
		shares = append(shares, KeyShareEntry{Group: GREASE_PLACEHOLDER, Data: []byte{0}})
	}
	if pq {
		shares = append(shares, KeyShareEntry{Group: X25519MLKEM768})
	}
	if p256First {
		shares = append(shares, KeyShareEntry{Group: CurveP256})
	} else {
		shares = append(shares, KeyShareEntry{Group: X25519})
	}

	versions := []uint16{VersionTLS12}
	if tls13 {
		versions = []uint16{VersionTLS13, VersionTLS12}
	}
	if grease {
		versions = append([]uint16{GREASE_PLACEHOLDER}, versions...)
	}

	exts := []TLSExtension{
		&SNIExtension{},
		&ExtendedMasterSecretExtension{},
		&RenegotiationInfoExtension{},
		&SupportedCurvesExtension{Curves: groups},
		&SupportedPointsExtension{SupportedPoints: []uint8{0}},
		&SessionTicketExtension{},
		&StatusRequestExtension{},
		&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
			ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256, ECDSAWithP384AndSHA384,
			PSSWithSHA384, PKCS1WithSHA384, PSSWithSHA512, PKCS1WithSHA512,
		}},
		&SCTExtension{},
		&SupportedVersionsExtension{Versions: versions},
	}
	if tls13 {
		exts = append(exts, &KeyShareExtension{KeyShares: shares}, &PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}})
	}
	if flip(w.ALPN) {
		exts = append(exts, &ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}})
	}
	if tls13 && flip(w.CertCompression) {
		exts = append(exts, &CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}})
	}
	if flip(w.ShuffleExtensions) {
		r.Shuffle(len(exts), func(i, j int) { exts[i], exts[j] = exts[j], exts[i] })
	}
	if grease {
		exts = append([]TLSExtension{&UtlsGREASEExtension{}}, exts...)
		exts = append(exts, &UtlsGREASEExtension{Body: []byte{0}})
	}
	if flip(w.Padding) {
		exts = append(exts, &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle})
	}
	return &ClientHelloSpec{CipherSuites: ciphers, CompressionMethods: []uint8{0}, Extensions: exts}, nil
}

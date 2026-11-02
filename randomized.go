// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	crand "crypto/rand"
	"math/rand/v2"
)

// Randomized fingerprints present a different, but always working, ClientHello
// each time. They are good at defeating fingerprint blocklists; because uTLS
// fully supports everything they offer, there is no parrot-is-dead risk. The
// survey showed downstream wants them constrained to negotiate consistently
// (always TLS 1.3-capable, X25519 offered), which these satisfy.
//
// HelloRandomized may or may not include ALPN; the ALPN/NoALPN variants pin it.
var (
	HelloRandomized       = register(ClientHelloID{Client: "Randomized", Version: "Auto", specFactory: func() (*ClientHelloSpec, error) { return randomizedSpec(randMode(2)) }}, "randomized", "random")
	HelloRandomizedALPN   = register(ClientHelloID{Client: "Randomized", Version: "ALPN", specFactory: func() (*ClientHelloSpec, error) { return randomizedSpec(1) }}, "randomized-alpn", "randomizedalpn")
	HelloRandomizedNoALPN = register(ClientHelloID{Client: "Randomized", Version: "NoALPN", specFactory: func() (*ClientHelloSpec, error) { return randomizedSpec(0) }}, "randomized-noalpn", "randomizednoalpn")
)

// newRand returns a *rand.Rand seeded from crypto/rand, so each generated
// fingerprint is unpredictable but the generation itself is cheap.
func newRand() *rand.Rand {
	var seed [32]byte
	crand.Read(seed[:]) //nolint:errcheck // crypto/rand.Read never fails here
	return rand.New(rand.NewChaCha8(seed))
}

// randMode(n): 0 = no ALPN, 1 = ALPN, 2 = coin-flip ALPN.
func randMode(n int) int { return n }

// randomizedSpec builds a valid, TLS 1.3-capable ClientHello with a shuffled
// extension order and a random cipher subset. alpnMode: 0 none, 1 present,
// 2 random.
func randomizedSpec(alpnMode int) (*ClientHelloSpec, error) {
	r := newRand()

	ciphers := []uint16{
		TLS_AES_128_GCM_SHA256,
		TLS_AES_256_GCM_SHA384,
		TLS_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	}
	// Keep the three TLS 1.3 suites, shuffle and sample the rest.
	tls13 := ciphers[:3]
	rest := append([]uint16(nil), ciphers[3:]...)
	r.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
	keep := 3 + r.IntN(len(rest)-2) // keep at least 3 legacy suites
	chosen := append(append([]uint16{}, tls13...), rest[:keep]...)

	sigAlgs := []SignatureScheme{
		ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
		ECDSAWithP384AndSHA384, PSSWithSHA384, PKCS1WithSHA384,
		PSSWithSHA512, PKCS1WithSHA512,
	}

	includeALPN := alpnMode == 1 || (alpnMode == 2 && r.IntN(2) == 0)

	// Mandatory extensions (order among these is shuffled), plus GREASE.
	exts := []TLSExtension{
		&SNIExtension{},
		&ExtendedMasterSecretExtension{},
		&RenegotiationInfoExtension{},
		&SupportedCurvesExtension{Curves: []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384}},
		&SupportedPointsExtension{SupportedPoints: []uint8{0}},
		&SessionTicketExtension{},
		&StatusRequestExtension{},
		&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigAlgs},
		&SCTExtension{},
		&KeyShareExtension{KeyShares: []KeyShareEntry{{Group: X25519MLKEM768}, {Group: X25519}}},
		&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
		&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
	}
	if includeALPN {
		exts = append(exts, &ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}})
	}
	if r.IntN(2) == 0 {
		exts = append(exts, &CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}})
	}
	r.Shuffle(len(exts), func(i, j int) { exts[i], exts[j] = exts[j], exts[i] })

	// GREASE bookends and padding stay at fixed positions (as browsers do).
	exts = append([]TLSExtension{&UtlsGREASEExtension{}}, exts...)
	exts = append(exts, &UtlsGREASEExtension{Body: []byte{0}}, &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle})

	// A GREASE cipher in front, like browsers.
	chosen = append([]uint16{GREASE_PLACEHOLDER}, chosen...)

	return &ClientHelloSpec{
		CipherSuites:       chosen,
		CompressionMethods: []uint8{0},
		Extensions:         exts,
	}, nil
}

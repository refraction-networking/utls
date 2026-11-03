// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/tls"
	"slices"
	"testing"
)

func extIDs(spec *ClientHelloSpec) []uint16 {
	var ids []uint16
	for _, e := range spec.Extensions {
		ids = append(ids, e.ID())
	}
	return ids
}

func TestSeededRandomizedIsDeterministic(t *testing.T) {
	seed, err := NewPRNGSeed()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := SeededRandomized(seed, nil).Spec()
	b, _ := SeededRandomized(seed, nil).Spec()
	if !slices.Equal(extIDs(a), extIDs(b)) || !slices.Equal(a.CipherSuites, b.CipherSuites) {
		t.Fatal("same seed produced different specs")
	}
	// The wire JA3 is stable too (GREASE is excluded by JA3).
	id := SeededRandomized(seed, nil)
	j1, _, _ := JA3(renderHello(t, id, "utls.test"))
	j2, _, _ := JA3(renderHello(t, id, "utls.test"))
	if j1 != j2 {
		t.Fatalf("seeded fingerprint JA3 varies:\n%s\n%s", j1, j2)
	}
	seed[0] ^= 1
	differs := false
	for i := 0; i < 8 && !differs; i++ {
		seed[1] = byte(i)
		c, _ := SeededRandomized(seed, nil).Spec()
		differs = !slices.Equal(extIDs(a), extIDs(c)) || !slices.Equal(a.CipherSuites, c.CipherSuites)
	}
	if !differs {
		t.Fatal("different seeds never produce different specs")
	}
}

func TestRandomizedWeights(t *testing.T) {
	always := &RandomizedWeights{ALPN: 1, TLS13: 1, PostQuantum: 0, FirstShareP256: 0, GREASE: 1}
	never := &RandomizedWeights{ALPN: 0, TLS13: 0, GREASE: 0}
	for i := 0; i < 50; i++ {
		var seed [32]byte
		seed[0], seed[1] = byte(i), 7
		s, _ := SeededRandomized(seed, always).Spec()
		if !hasExtension(s, 16) || !hasExtension(s, 51) || hasExtension(s, 21) && false {
			t.Fatal("ALPN/TLS1.3 weight 1 not honored")
		}
		for _, e := range s.Extensions {
			if ks, ok := e.(*KeyShareExtension); ok && ks.KeyShares[len(ks.KeyShares)-1].Group != X25519 {
				t.Fatal("X25519 classical share not used with FirstShareP256=0")
			}
			if c, ok := e.(*SupportedCurvesExtension); ok && slices.Contains(c.Curves, X25519MLKEM768) {
				t.Fatal("PQ offered with weight 0")
			}
		}
		n, _ := SeededRandomized(seed, never).Spec()
		if hasExtension(n, 16) || hasExtension(n, 51) || slices.Contains(n.CipherSuites, GREASE_PLACEHOLDER) {
			t.Fatal("weight 0 not honored")
		}
	}
}

func TestRandomizedAlwaysHandshakes(t *testing.T) {
	for _, base := range []ClientHelloID{HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN} {
		for i := 0; i < 12; i++ {
			for _, max := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
				scfg := serverConfig(t)
				scfg.MaxVersion = max
				handshakeStd(t, base, clientConfig(t), scfg, nil).ok(t)
			}
		}
	}
}

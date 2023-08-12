// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"context"
	"fmt"
	"testing"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/hybrid"
)

func testHybridKEX(t *testing.T, scheme kem.Scheme, clientPQ, serverPQ,
	clientTLS12, serverTLS12 bool) {
	// var clientSelectedKEX *CurveID
	// var retry bool

	rsaCert := Certificate{
		Certificate: [][]byte{testRSACertificate},
		PrivateKey:  testRSAPrivateKey,
	}
	serverCerts := []Certificate{rsaCert}

	clientConfig := testConfig.Clone()
	if clientPQ {
		clientConfig.CurvePreferences = []CurveID{
			kemSchemeKeyToCurveID(scheme),
			X25519,
		}
	}
	// clientCFEventHandler := func(ev CFEvent) {
	// 	switch e := ev.(type) {
	// 	case CFEventTLSNegotiatedNamedKEX:
	// 		clientSelectedKEX = &e.KEX
	// 	case CFEventTLS13HRR:
	// 		retry = true
	// 	}
	// }
	if clientTLS12 {
		clientConfig.MaxVersion = VersionTLS12
	}

	serverConfig := testConfig.Clone()
	if serverPQ {
		serverConfig.CurvePreferences = []CurveID{
			kemSchemeKeyToCurveID(scheme),
			X25519,
		}
	}
	if serverTLS12 {
		serverConfig.MaxVersion = VersionTLS12
	}
	serverConfig.Certificates = serverCerts

	c, s := localPipe(t)
	done := make(chan error)
	defer c.Close()

	go func() {
		defer s.Close()
		done <- Server(s, serverConfig).Handshake()
	}()

	cli := Client(c, clientConfig)
	// cCtx := context.WithValue(context.Background(), CFEventHandlerContextKey{}, clientCFEventHandler)
	clientErr := cli.HandshakeContext(context.Background())
	serverErr := <-done
	if clientErr != nil {
		t.Errorf("client error: %s", clientErr)
	}
	if serverErr != nil {
		t.Errorf("server error: %s", serverErr)
	}

	// var expectedKEX CurveID
	// var expectedRetry bool

	// if clientPQ && serverPQ && !clientTLS12 && !serverTLS12 {
	// 	expectedKEX = kemSchemeKeyToCurveID(scheme)
	// } else {
	// 	expectedKEX = X25519
	// }
	// if !clientTLS12 && clientPQ && !serverPQ {
	// 	expectedRetry = true
	// }

	// if clientSelectedKEX == nil {
	// 	t.Error("No KEX happened?")
	// }

	// if *clientSelectedKEX != expectedKEX {
	// 	t.Errorf("failed to negotiate: expected %d, got %d",
	// 		expectedKEX, *clientSelectedKEX)
	// }
	// if expectedRetry != retry {
	// 	t.Errorf("Expected retry=%v, got retry=%v", expectedRetry, retry)
	// }
}

func TestHybridKEX(t *testing.T) {
	run := func(scheme kem.Scheme, clientPQ, serverPQ, clientTLS12, serverTLS12 bool) {
		t.Run(fmt.Sprintf("%s serverPQ:%v clientPQ:%v serverTLS12:%v clientTLS12:%v", scheme.Name(),
			serverPQ, clientPQ, serverTLS12, clientTLS12), func(t *testing.T) {
			testHybridKEX(t, scheme, clientPQ, serverPQ, clientTLS12, serverTLS12)
		})
	}
	for _, scheme := range []kem.Scheme{
		hybrid.Kyber512X25519(),
		hybrid.Kyber768X25519(),
		hybrid.P256Kyber768Draft00(),
	} {
		run(scheme, true, true, false, false)
		run(scheme, true, false, false, false)
		run(scheme, false, true, false, false)
		run(scheme, true, true, true, false)
		run(scheme, true, true, false, true)
		run(scheme, true, true, true, true)
	}
}

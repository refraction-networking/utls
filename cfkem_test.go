// Copyright 2022 Cloudflare, Inc. All rights reserved. Use of this source code
// is governed by a BSD-style license that can be found in the LICENSE file.

package tls

import (
	"context"
	"fmt"
	"testing"
)

func testHybridKEX(t *testing.T, curveID CurveID, clientPQ, serverPQ,
	clientTLS12, serverTLS12 bool) {
	// var clientSelectedKEX *CurveID
	// var retry bool

	clientConfig := testConfig.Clone()
	if clientPQ {
		clientConfig.CurvePreferences = []CurveID{curveID, X25519}
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
		serverConfig.CurvePreferences = []CurveID{curveID, X25519}
	} else {
		serverConfig.CurvePreferences = []CurveID{X25519}
	}
	if serverTLS12 {
		serverConfig.MaxVersion = VersionTLS12
	}

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
	// 	expectedKEX = curveID
	// } else {
	// 	expectedKEX = X25519
	// }
	// if !clientTLS12 && clientPQ && !serverPQ {
	// 	expectedRetry = true
	// }

	// if expectedRetry != retry {
	// 	t.Errorf("Expected retry=%v, got retry=%v", expectedRetry, retry)
	// }

	// if clientSelectedKEX == nil {
	// 	t.Error("No KEX happened?")
	// } else if *clientSelectedKEX != expectedKEX {
	// 	t.Errorf("failed to negotiate: expected %d, got %d",
	// 		expectedKEX, *clientSelectedKEX)
	// }
}

func TestHybridKEX(t *testing.T) {
	run := func(curveID CurveID, clientPQ, serverPQ, clientTLS12, serverTLS12 bool) {
		t.Run(fmt.Sprintf("%#04x serverPQ:%v clientPQ:%v serverTLS12:%v clientTLS12:%v", uint16(curveID),
			serverPQ, clientPQ, serverTLS12, clientTLS12), func(t *testing.T) {
			testHybridKEX(t, curveID, clientPQ, serverPQ, clientTLS12, serverTLS12)
		})
	}
	for _, curveID := range []CurveID{
		X25519Kyber512Draft00,
		X25519Kyber768Draft00,
		X25519Kyber768Draft00Old,
		P256Kyber768Draft00,
	} {
		run(curveID, true, true, false, false)
		run(curveID, true, false, false, false)
		run(curveID, false, true, false, false)
		run(curveID, true, true, true, false)
		run(curveID, true, true, false, true)
		run(curveID, true, true, true, true)
	}
}

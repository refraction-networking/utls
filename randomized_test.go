// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// Randomized fingerprints must always produce a working handshake.
func TestRandomizedAlwaysHandshakes(t *testing.T) {
	addr, roots := testServer(t, &tls.Config{NextProtos: []string{"h2", "http/1.1"}})
	for _, id := range []ClientHelloID{HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN} {
		for i := 0; i < 8; i++ {
			cfg := &tls.Config{ServerName: "utls.test", RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}}
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			uc := UClient(conn, cfg, id)
			if err := uc.Handshake(); err != nil {
				t.Fatalf("%s iter %d: handshake failed: %v", id.Str(), i, err)
			}
			uc.Close()
		}
	}
}

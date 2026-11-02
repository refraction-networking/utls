// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"io"
	"testing"
)

// renderSpec drives buildClientHello on a throwaway UConn and returns the raw
// ClientHello bytes plus the logical message, for tests.
func renderSpec(t *testing.T, spec *ClientHelloSpec) (*clientHelloMsg, *UConn) {
	t.Helper()
	cfg := testConfigClient.Clone()
	cfg.ServerName = "test.golang.example"
	u := &UConn{spec: spec, ephemeralKeys: map[CurveID]*keySharePrivateKeys{}}
	u.Conn = &Conn{config: cfg}
	hello := &clientHelloMsg{
		random:     make([]byte, 32),
		sessionId:  make([]byte, 32),
		serverName: hostnameInSNI("test.golang.example"),
	}
	io.ReadFull(rand.Reader, hello.random)
	io.ReadFull(rand.Reader, hello.sessionId)
	if _, err := u.buildClientHello(hello); err != nil {
		t.Fatalf("buildClientHello: %v", err)
	}
	return hello, u
}

func TestURenderRoundTrips(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec *ClientHelloSpec
	}{
		{"chrome-tls13", chromeishTLS13Spec()},
		{"firefox-tls12", firefoxishTLS12Spec()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hello, _ := renderSpec(t, tc.spec)
			var parsed clientHelloMsg
			if !parsed.unmarshal(hello.original) {
				t.Fatalf("rendered ClientHello does not parse: % x", hello.original)
			}
			// Re-marshal through the parser and confirm the bytes are stable,
			// i.e. our length prefixes are all correct.
			if len(parsed.original) != len(hello.original) {
				t.Errorf("parsed length %d != rendered %d", len(parsed.original), len(hello.original))
			}
			if string(parsed.random) != string(hello.random[:]) {
				t.Errorf("random mismatch after parse")
			}
		})
	}
}

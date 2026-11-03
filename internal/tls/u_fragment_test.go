// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"testing"
)

func FuzzSNIHostRange(f *testing.F) {
	m := &clientHelloMsg{vers: VersionTLS12, random: make([]byte, 32), sessionId: make([]byte, 32),
		cipherSuites: []uint16{TLS_AES_128_GCM_SHA256}, compressionMethods: []uint8{0}, serverName: "example.com",
		supportedVersions: []uint16{VersionTLS13}}
	raw, err := m.marshal()
	if err != nil {
		f.Fatal(err)
	}
	s, e, ok := sniHostRange(raw)
	if !ok || string(raw[s:e]) != "example.com" {
		f.Fatalf("sniHostRange = %d,%d,%v", s, e, ok)
	}
	f.Add(raw)
	f.Add(raw[:len(raw)/2])
	f.Fuzz(func(t *testing.T, b []byte) {
		s, e, ok := sniHostRange(b)
		if !ok {
			return
		}
		if s < 0 || e > len(b) || s >= e {
			t.Fatalf("bad range %d,%d of %d", s, e, len(b))
		}
		if bytes.IndexByte(b[s:e], 0) == -2 { // touch the bytes
			t.Fatal()
		}
	})
}

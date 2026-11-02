// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	itls "github.com/refraction-networking/utls/internal/tls"
)

// renderBytes returns the raw ClientHello a preset would send.
func renderBytes(t *testing.T, id ClientHelloID) []byte {
	t.Helper()
	spec, err := id.Spec()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{ServerName: "fp.test"}
	u := itls.NewUConn(nil, fromStdConfig(cfg), spec)
	raw, err := u.RenderClientHelloForTest(mustRand(t, 32), mustRand(t, 32))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return raw
}

func mustRand(t *testing.T, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatal(err)
	}
	return b
}

// normExtID normalizes an extension's identity for comparison: every GREASE
// extension maps to GREASE_PLACEHOLDER (its drawn value differs per render, and
// an unrendered spec reports 0), so two specs with GREASE in the same slot
// compare equal.
func normExtID(e TLSExtension) uint16 {
	if _, ok := e.(*UtlsGREASEExtension); ok {
		return GREASE_PLACEHOLDER
	}
	if isGREASE(e.ID()) {
		return GREASE_PLACEHOLDER
	}
	return e.ID()
}

func extIDs(spec *ClientHelloSpec) []uint16 {
	ids := make([]uint16, len(spec.Extensions))
	for i, e := range spec.Extensions {
		ids[i] = normExtID(e)
	}
	return ids
}

func TestFingerprinterRoundTrip(t *testing.T) {
	for _, id := range []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto, HelloSafari_Auto} {
		t.Run(id.Str(), func(t *testing.T) {
			raw := renderBytes(t, id)
			parsed, err := ParseClientHello(raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			orig, _ := id.Spec()
			og, pg := extIDs(orig), extIDs(parsed)
			if len(og) != len(pg) {
				t.Fatalf("extension count: orig %d parsed %d", len(og), len(pg))
			}
			for i := range og {
				if og[i] != pg[i] {
					t.Errorf("ext %d: orig %#x parsed %#x", i, og[i], pg[i])
				}
			}
		})
	}
}

// TestFingerprinterDialable confirms a parsed spec actually handshakes (fresh
// key material is generated for the parsed key_share groups).
func TestFingerprinterDialable(t *testing.T) {
	addr, roots := testServer(t, &tls.Config{NextProtos: []string{"h2"}})
	raw := renderBytes(t, HelloChrome_Auto)
	spec, err := ParseClientHello(raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{ServerName: "utls.test", RootCAs: roots, NextProtos: []string{"h2"}}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	uc := UClient(conn, cfg, HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := uc.Handshake(); err != nil {
		t.Fatalf("handshake with parsed spec: %v", err)
	}
	defer uc.Close()
	if !uc.ConnectionState().HandshakeComplete {
		t.Fatal("handshake incomplete")
	}
}

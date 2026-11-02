// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

// testServer starts a standard crypto/tls server on loopback with a fresh
// self-signed cert, so the tests exercise uTLS-client ↔ stdlib-server interop.
func testServer(t *testing.T, cfg *tls.Config) (addr string, roots *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "utls.test"},
		DNSNames:     []string{"utls.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots = x509.NewCertPool()
	roots.AddCert(leaf)

	if cfg == nil {
		cfg = &tls.Config{}
	}
	cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				tc := c.(*tls.Conn)
				if tc.Handshake() == nil {
					tc.Write([]byte("hi"))
				}
			}(c)
		}
	}()
	return ln.Addr().String(), roots
}

func TestDialPresetsInterop(t *testing.T) {
	addr, roots := testServer(t, &tls.Config{NextProtos: []string{"h2", "http/1.1"}})

	presets := []struct {
		name string
		id   ClientHelloID
		min  uint16
	}{
		{"Chrome", HelloChrome_Auto, VersionTLS13},
		{"Firefox", HelloFirefox_Auto, VersionTLS13},
		{"Safari", HelloSafari_Auto, VersionTLS13},
		{"Golang", HelloGolang, VersionTLS12},
	}
	for _, p := range presets {
		t.Run(p.name, func(t *testing.T) {
			cfg := &tls.Config{ServerName: "utls.test", RootCAs: roots, NextProtos: []string{"h2", "http/1.1"}}
			uc, err := Dial("tcp", addr, cfg, p.id)
			if err != nil {
				t.Fatalf("Dial %s: %v", p.name, err)
			}
			defer uc.Close()
			cs := uc.ConnectionState()
			if !cs.HandshakeComplete {
				t.Fatal("handshake not complete")
			}
			if cs.Version < p.min {
				t.Errorf("version = %x, want >= %x", cs.Version, p.min)
			}
			if cs.NegotiatedProtocol != "h2" {
				t.Errorf("ALPN = %q, want h2", cs.NegotiatedProtocol)
			}
			buf := make([]byte, 2)
			if _, err := uc.Read(buf); err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(buf) != "hi" {
				t.Errorf("read %q, want hi", buf)
			}
		})
	}
}

func TestParseFingerprint(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
	}{
		{"", "Chrome-Auto"},
		{"chrome", "Chrome-Auto"},
		{"Chrome-Auto", "Chrome-Auto"},
		{"FIREFOX", "Firefox-Auto"},
		{"safari", "Safari-Auto"},
		{"golang", "Golang-Auto"},
		{"none", "Golang-Auto"},
		{"edge", "Edge-Auto"},
	} {
		got, err := ParseFingerprint(tc.in)
		if err != nil {
			t.Errorf("ParseFingerprint(%q): %v", tc.in, err)
			continue
		}
		if got.Str() != tc.want {
			t.Errorf("ParseFingerprint(%q) = %q, want %q", tc.in, got.Str(), tc.want)
		}
	}
	if _, err := ParseFingerprint("nonsense"); err == nil {
		t.Error("expected error for unknown fingerprint")
	}
}

func TestClientHelloHookEndToEnd(t *testing.T) {
	addr, roots := testServer(t, nil)
	cfg := &tls.Config{ServerName: "utls.test", RootCAs: roots}
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	uc := UClient(raw, cfg, HelloChrome_Auto)
	var ran bool
	uc.SetClientHelloHook(func(h *ClientHelloContext) error {
		ran = true
		if h.EphemeralKey(X25519) == nil {
			t.Error("no X25519 ephemeral key available to hook")
		}
		// Overwrite session_id with a marker (REALITY-style).
		for i := range h.SessionID {
			h.SessionID[i] = 0x42
		}
		return nil
	})
	if err := uc.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer uc.Close()
	if !ran {
		t.Fatal("hook did not run")
	}
}

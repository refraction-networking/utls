// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/tls"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// versionSpec offers exactly versions (nil: no supported_versions extension,
// i.e. a legacy TLS 1.2 hello) with TLS 1.3 and 1.2 suites and an X25519 share.
func versionSpec(versions []uint16) func() (*ClientHelloSpec, error) {
	return func() (*ClientHelloSpec, error) {
		exts := []TLSExtension{
			&SNIExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256}},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
		}
		if versions != nil {
			exts = append(exts, &SupportedVersionsExtension{Versions: versions},
				&KeyShareExtension{KeyShares: []KeyShareEntry{{Group: X25519}}})
		}
		return &ClientHelloSpec{
			CipherSuites: []uint16{TLS_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
			CompressionMethods: []uint8{0},
			Extensions:         exts,
		}, nil
	}
}

// scriptedServerHello answers the first ClientHello with a ServerHello that
// selects legacy version vers and, if sv != 0, supported_versions sv; it then
// reports the first record the client sends back (an alert, if rejected).
func scriptedServerHello(t *testing.T, vers, sv uint16) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	out := make(chan []byte, 1)
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			out <- nil
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		h, err := peekHello(c)
		if err != nil {
			out <- nil
			return
		}
		suite := uint16(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
		if sv == tls.VersionTLS13 {
			suite = tls.TLS_AES_128_GCM_SHA256
		}
		var b cryptobyte.Builder
		b.AddUint8(2) // server_hello
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(vers)
			b.AddBytes(make([]byte, 32)) // random without downgrade canaries
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				if sv == tls.VersionTLS13 {
					b.AddBytes(h.sid) // TLS 1.3 echoes the compatibility session ID
				}
			})
			b.AddUint16(suite)
			b.AddUint8(0)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				if sv != 0 {
					b.AddUint16(43)
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(sv) })
				}
				b.AddUint16(0xff01) // renegotiation_info
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint8(0) })
			})
		})
		msg := b.BytesOrPanic()
		rec := append([]byte{22, 3, 3, byte(len(msg) >> 8), byte(len(msg))}, msg...)
		c.Write(rec)
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			out <- nil
			return
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		io.ReadFull(c, body)
		out <- append(hdr, body...)
	}()
	return ln.Addr().String(), out
}

func TestServerVersionMustHaveBeenOffered(t *testing.T) {
	for _, tc := range []struct {
		name    string
		offered []uint16 // nil: no supported_versions extension
		vers    uint16   // ServerHello.legacy_version
		sv      uint16   // ServerHello supported_versions (0: absent)
	}{
		{"offered 1.3 only, server picks lower 1.2", []uint16{tls.VersionTLS13}, tls.VersionTLS12, 0},
		{"offered 1.2 only, server picks higher 1.3", []uint16{tls.VersionTLS12}, tls.VersionTLS12, tls.VersionTLS13},
		{"noncontiguous 1.3+1.1, server picks 1.2", []uint16{tls.VersionTLS13, tls.VersionTLS11}, tls.VersionTLS12, 0},
		{"noncontiguous 1.3+1.1, server picks 1.0", []uint16{tls.VersionTLS13, tls.VersionTLS11}, tls.VersionTLS10, 0},
		{"noncontiguous 1.3+1.1 with GREASE, server picks 1.2 via extension", []uint16{GREASE_PLACEHOLDER, tls.VersionTLS13, tls.VersionTLS11}, tls.VersionTLS12, tls.VersionTLS12},
		{"no supported_versions, server picks 1.3", nil, tls.VersionTLS12, tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, got := scriptedServerHello(t, tc.vers, tc.sv)
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			cfg := clientConfig(t)
			cfg.MinVersion, cfg.MaxVersion = tls.VersionTLS10, tls.VersionTLS13 // Config allows them all
			uc := UClient(conn, cfg, CustomFingerprint("Versions", tc.name, versionSpec(tc.offered)))
			uc.SetDeadline(time.Now().Add(5 * time.Second))
			err = uc.Handshake()
			if err == nil || !strings.Contains(err.Error(), "did not offer") {
				t.Fatalf("handshake error %v, want rejection of the unoffered version", err)
			}
			// The client answered with a fatal protocol_version alert.
			if r := <-got; len(r) < 7 || r[0] != 21 || r[5] != 2 || r[6] != 70 {
				t.Fatalf("client sent %x, want a protocol_version alert", r)
			}
		})
	}
}

// Offered noncontiguous versions still negotiate when the server picks one
// that was offered.
func TestNoncontiguousOfferedVersionNegotiates(t *testing.T) {
	scfg := serverConfig(t)
	// Server max 1.1: no downgrade canary (a 1.2-capable server negotiating
	// 1.1 with a client that offered 1.3 correctly triggers RFC 8446 4.1.3).
	scfg.MinVersion, scfg.MaxVersion = tls.VersionTLS10, tls.VersionTLS11
	ccfg := clientConfig(t)
	ccfg.MinVersion = tls.VersionTLS10
	id := CustomFingerprint("Versions", "1.3+1.1", versionSpec([]uint16{tls.VersionTLS13, tls.VersionTLS11}))
	r := handshakeStd(t, id, ccfg, scfg, nil)
	r.ok(t)
	if v := r.uc.ConnectionState().Version; v != tls.VersionTLS11 {
		t.Fatalf("negotiated %x, want TLS 1.1 (the only offered version the server supports)", v)
	}
}

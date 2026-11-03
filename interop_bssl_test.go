// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build bsslinterop

// Interop against an independent BoringSSL server (interop/boringssl/peer.cc):
// real zlib certificate compression and ALPS chosen by a non-Go TLS stack.
//
//	BORINGSSL=... OUT=... sh interop/boringssl/build.sh
//	UTLS_BSSL_PEER=$OUT/utls-bssl-peer go test -tags bsslinterop -run BoringSSL .

package utls

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func startBSSLPeer(t *testing.T, args ...string) string {
	peer := os.Getenv("UTLS_BSSL_PEER")
	if peer == "" {
		t.Fatal("UTLS_BSSL_PEER not set (see interop/boringssl/build.sh)")
	}
	dir := t.TempDir()
	p := getPKI(t)
	var chain []byte
	for _, der := range p.cert.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	kb, _ := x509.MarshalECPrivateKey(p.cert.PrivateKey.(*ecdsa.PrivateKey))
	os.WriteFile(filepath.Join(dir, "cert.pem"), chain, 0o600)
	os.WriteFile(filepath.Join(dir, "key.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	cmd := exec.Command(peer, append([]string{"-cert", filepath.Join(dir, "cert.pem"), "-key", filepath.Join(dir, "key.pem")}, args...)...)
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "PORT ") {
		t.Fatalf("peer did not start: %q %v", line, err)
	}
	return "127.0.0.1:" + strings.TrimSpace(strings.TrimPrefix(line, "PORT "))
}

func bsslDial(t *testing.T, addr string, id ClientHelloID) (*UConn, string) {
	t.Helper()
	cfg := clientConfig(t)
	cfg.NextProtos = nil
	uc, err := Dial("tcp", addr, cfg, id)
	if err != nil {
		t.Fatalf("%s: %v", id.Str(), err)
	}
	uc.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(uc).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	uc.Write([]byte("bye"))
	return uc, strings.TrimSpace(line)
}

func TestBoringSSLCertificateCompression(t *testing.T) {
	addr := startBSSLPeer(t, "-zlib")
	uc, status := bsslDial(t, addr, HelloFirefox_148) // offers zlib, brotli, zstd
	defer uc.Close()
	if !strings.Contains(status, "compressed=1") || len(uc.ConnectionState().PeerCertificates) == 0 {
		t.Fatalf("zlib-compressed certificate not negotiated/verified: %s", status)
	}
	t.Logf("firefox148 vs BoringSSL: %s", status)
	// Chrome offers only brotli: the zlib-only peer must not compress.
	uc2, status2 := bsslDial(t, addr, HelloChrome_155)
	defer uc2.Close()
	if !strings.Contains(status2, "compressed=0") {
		t.Fatalf("compression used without a common algorithm: %s", status2)
	}
}

func TestBoringSSLALPS(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   ClientHelloID
		args []string
		want bool
	}{
		{"chrome155-new", HelloChrome_155, []string{"-alps", "h2=0a0b", "-alps-new"}, true},
		{"qq-old", HelloQQ_11_1, []string{"-alps", "h2=0a0b"}, true},
		{"codepoint-mismatch", HelloChrome_155, []string{"-alps", "h2=0a0b"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr := startBSSLPeer(t, tc.args...)
			uc, status := bsslDial(t, addr, tc.id)
			defer uc.Close()
			settings, ok := uc.NegotiatedApplicationSettings()
			if ok != tc.want {
				t.Fatalf("ALPS negotiated=%v want %v (%s)", ok, tc.want, status)
			}
			if tc.want && (string(settings) != "\x0a\x0b" || !strings.Contains(status, "alps=empty") || !strings.Contains(status, "alpn=h2")) {
				t.Fatalf("settings %x status %s", settings, status)
			}
			t.Logf("%s: %s", tc.name, status)
		})
	}
}

var _ = io.EOF
var _ = tls.VersionTLS13

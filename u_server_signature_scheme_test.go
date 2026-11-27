// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
)

func TestServerSignatureSchemeOverrideTLS13(t *testing.T) {
	clientConfig := testConfigClient.Clone()
	serverConfig := testConfigServer.Clone()
	serverConfig.Certificates = []Certificate{testECDSAP256Cert, testEd25519Cert}
	var called bool
	serverConfig.SelectServerSignatureScheme = func(hello *ClientHelloInfo, cert *Certificate, version uint16) (SignatureScheme, error) {
		called = true
		if version != VersionTLS13 {
			t.Errorf("negotiated version = %x, want TLS 1.3", version)
		}
		if len(hello.SignatureSchemes) != 1 || hello.SignatureSchemes[0] != ECDSAWithP256AndSHA256 {
			t.Errorf("client signature schemes = %v", hello.SignatureSchemes)
		}
		return Ed25519, nil
	}
	serverConfig = serverConfig.Clone()

	serverState, clientState, err := testUtlsHandshake(t, clientConfig, serverConfig,
		go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256}))
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("SelectServerSignatureScheme was not called")
	}
	if serverState.Version != VersionTLS13 || clientState.Version != VersionTLS13 {
		t.Fatalf("negotiated versions: server=%x client=%x", serverState.Version, clientState.Version)
	}
	if len(clientState.PeerCertificates) == 0 {
		t.Fatal("client received no certificate")
	}
	if _, ok := clientState.PeerCertificates[0].PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("selected certificate public key = %T, want Ed25519", clientState.PeerCertificates[0].PublicKey)
	}
}

func TestServerSignatureSchemeOverrideValidation(t *testing.T) {
	hello := &ClientHelloInfo{SignatureSchemes: []SignatureScheme{ECDSAWithP256AndSHA256}}
	cert := &testEd25519Cert
	config := &Config{}
	if _, err := config.selectServerSignatureScheme(hello, cert, VersionTLS13); err == nil {
		t.Fatal("default selection accepted an unadvertised scheme")
	}

	config.SelectServerSignatureScheme = func(*ClientHelloInfo, *Certificate, uint16) (SignatureScheme, error) {
		return Ed25519, nil
	}
	if got, err := config.selectServerSignatureScheme(hello, cert, VersionTLS13); err != nil || got != Ed25519 {
		t.Fatalf("override = %v, %v; want Ed25519", got, err)
	}

	for _, scheme := range []SignatureScheme{ECDSAWithP256AndSHA256, MLDSA44} {
		config.SelectServerSignatureScheme = func(*ClientHelloInfo, *Certificate, uint16) (SignatureScheme, error) {
			return scheme, nil
		}
		if _, err := config.selectServerSignatureScheme(hello, cert, VersionTLS13); err == nil {
			t.Errorf("accepted incompatible scheme %x", scheme)
		}
	}

	wantErr := errors.New("application rejected scheme")
	config.SelectServerSignatureScheme = func(*ClientHelloInfo, *Certificate, uint16) (SignatureScheme, error) {
		return 0, wantErr
	}
	if _, err := config.selectServerSignatureScheme(hello, cert, VersionTLS13); !errors.Is(err, wantErr) {
		t.Fatalf("callback error = %v, want %v", err, wantErr)
	}

	hello.SignatureSchemes = nil
	if _, err := config.selectServerSignatureScheme(hello, cert, VersionTLS12); err == nil || !strings.Contains(err.Error(), "missing signature_algorithms") {
		t.Fatalf("TLS 1.2 missing extension error = %v", err)
	}
}

func TestServerSignatureSchemeOverrideTLS12KeyAgreement(t *testing.T) {
	config := &Config{CurvePreferences: []CurveID{CurveP256}}
	config.SelectServerSignatureScheme = func(hello *ClientHelloInfo, cert *Certificate, version uint16) (SignatureScheme, error) {
		if version != VersionTLS12 || cert != &testEd25519Cert {
			t.Errorf("callback received version %x, certificate %p", version, cert)
		}
		return Ed25519, nil
	}
	hello := &clientHelloMsg{
		random:                       make([]byte, 32),
		supportedCurves:              []CurveID{CurveP256},
		supportedSignatureAlgorithms: []SignatureScheme{ECDSAWithP256AndSHA256},
	}
	info := &ClientHelloInfo{SignatureSchemes: hello.supportedSignatureAlgorithms}
	ka := &ecdheKeyAgreement{version: VersionTLS12}
	skx, err := ka.generateServerKeyExchange(config, &testEd25519Cert, hello,
		&serverHelloMsg{random: make([]byte, 32)}, info)
	if err != nil {
		t.Fatal(err)
	}
	if skx == nil || ka.signatureAlgorithm != Ed25519 {
		t.Fatalf("ServerKeyExchange = %v, scheme = %x; want Ed25519", skx, ka.signatureAlgorithm)
	}
}

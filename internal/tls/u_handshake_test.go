// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"testing"
	"time"
)

// chromeishTLS13Spec is a minimal TLS 1.3 ClientHello with GREASE, a hybrid +
// classical key share, and the extensions a modern browser sends. It is enough
// to exercise the renderer and the key-share/HRR hooks; the public package
// ships the real, full fingerprints.
func chromeishTLS13Spec() *ClientHelloSpec {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			GREASEPlaceholder,
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{GREASEPlaceholder, X25519MLKEM768, X25519, CurveP256}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&SessionTicketExtension{},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
				ECDSAWithP384AndSHA384, PSSWithSHA384, PKCS1WithSHA384,
				PSSWithSHA512, PKCS1WithSHA512,
			}},
			&SCTExtension{},
			&KeyShareExtension{KeyShares: []KeyShareEntry{
				{Group: CurveID(GREASEPlaceholder), Data: []byte{0}},
				{Group: X25519MLKEM768},
				{Group: X25519},
			}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASEPlaceholder, VersionTLS13, VersionTLS12}},
			&CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
			&UtlsGREASEExtension{Body: []byte{0}},
			&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
		},
	}
}

func firefoxishTLS12Spec() *ClientHelloSpec {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		CompressionMethods: []uint8{0},
		TLSVersMax:         VersionTLS12,
		Extensions: []TLSExtension{
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256, CurveP384}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&SessionTicketExtension{},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384,
				PSSWithSHA256, PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512,
			}},
		},
	}
}

func uHandshakePipe(t *testing.T, spec *ClientHelloSpec, hook func(*ClientHelloContext) error, serverMax uint16) (clientState, serverState ConnectionState, err error) {
	t.Helper()
	cConn, sConn := localPipe(t)

	clientCfg := testConfigClient.Clone()
	clientCfg.ServerName = "test.golang.example"

	_ = cConn.SetDeadline(time.Now().Add(10 * time.Second))
	_ = sConn.SetDeadline(time.Now().Add(10 * time.Second))

	uc := NewUConn(cConn, clientCfg, spec)
	if hook != nil {
		uc.SetClientHelloHook(hook)
	}

	srvCfg := testConfigServer.Clone()
	srvCfg.NextProtos = []string{"h2", "http/1.1"}
	if serverMax != 0 {
		srvCfg.MaxVersion = serverMax
	}
	srv := Server(sConn, srvCfg)

	errc := make(chan error, 1)
	go func() {
		errc <- srv.HandshakeContext(context.Background())
	}()

	err = uc.HandshakeContext(context.Background())
	serr := <-errc
	if err == nil {
		err = serr
	}
	if err != nil {
		return
	}
	clientState = uc.ConnectionState()
	serverState = srv.ConnectionState()
	_ = uc.Close()
	_ = srv.Close()
	return
}

func TestURenderTLS13Handshake(t *testing.T) {
	cs, ss, err := uHandshakePipe(t, chromeishTLS13Spec(), nil, 0)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if cs.Version != VersionTLS13 {
		t.Errorf("client negotiated version %x, want TLS 1.3", cs.Version)
	}
	if ss.Version != VersionTLS13 {
		t.Errorf("server negotiated version %x, want TLS 1.3", ss.Version)
	}
	if cs.NegotiatedProtocol != "h2" {
		t.Errorf("ALPN = %q, want h2", cs.NegotiatedProtocol)
	}
}

func TestURenderTLS12Handshake(t *testing.T) {
	cs, _, err := uHandshakePipe(t, firefoxishTLS12Spec(), nil, VersionTLS12)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if cs.Version != VersionTLS12 {
		t.Errorf("client negotiated version %x, want TLS 1.2", cs.Version)
	}
}

func TestUClientHelloHookSessionID(t *testing.T) {
	// A REALITY/ShadowTLS-style hook: overwrite session_id with a marker and
	// confirm the handshake still completes (the server echoes nothing back for
	// TLS 1.3 session_id beyond the compatibility value).
	marker := make([]byte, 32)
	for i := range marker {
		marker[i] = byte(i)
	}
	var sawEphemeral bool
	hook := func(h *ClientHelloContext) error {
		if len(h.SessionID) != 32 {
			return errors.New("expected 32-byte session_id")
		}
		if h.EphemeralKey(X25519MLKEM768) == nil {
			return errors.New("expected X25519MLKEM768 ephemeral key")
		}
		sawEphemeral = true
		copy(h.SessionID, marker)
		return nil
	}
	_, _, err := uHandshakePipe(t, chromeishTLS13Spec(), hook, 0)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}
	if !sawEphemeral {
		t.Fatal("hook did not run")
	}
}

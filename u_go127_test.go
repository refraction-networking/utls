// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/fips140"
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

func TestUQUICDefaultMinVersion(t *testing.T) {
	for _, helloID := range []ClientHelloID{HelloGolang, HelloCustom} {
		t.Run(helloID.Str(), func(t *testing.T) {
			infoConn, peerConn := net.Pipe()
			defer infoConn.Close()
			defer peerConn.Close()

			clientConfig := testConfigClient.Clone()
			clientConfig.NextProtos = []string{"h3"}
			client := UQUICClient(&QUICConfig{
				TLSConfig:           clientConfig,
				ClientHelloInfoConn: infoConn,
			}, helloID)
			defer client.Close()
			if client.conn.quic.clientHelloInfoConn != infoConn {
				t.Fatal("UQUICClient did not retain ClientHelloInfoConn")
			}
			if helloID == HelloCustom {
				preset := go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256})
				preset.Extensions = append(preset.Extensions,
					&ALPNExtension{AlpnProtocols: []string{"h3"}},
					&QUICTransportParametersExtension{},
				)
				if err := client.ApplyPreset(preset); err != nil {
					t.Fatal(err)
				}
			}
			client.SetTransportParameters(nil)

			serverConfig := testConfigServer.Clone()
			serverConfig.NextProtos = []string{"h3"}
			var callbackCalled bool
			serverConfig.GetConfigForClient = func(info *ClientHelloInfo) (*Config, error) {
				callbackCalled = true
				if info.Conn != infoConn {
					t.Error("ClientHelloInfo.Conn did not use ClientHelloInfoConn")
				}
				if !slices.Equal(info.SupportedVersions, []uint16{VersionTLS13}) {
					t.Errorf("QUIC advertised versions %x, want TLS 1.3 only", info.SupportedVersions)
				}
				return nil, nil
			}
			server := QUICServer(&QUICConfig{
				TLSConfig:           serverConfig,
				ClientHelloInfoConn: infoConn,
			})
			defer server.Close()
			server.SetTransportParameters(nil)

			// Exercise UQUICConn's event methods as well as its custom handshake.
			type quicEndpoint interface {
				Start(context.Context) error
				NextEvent() QUICEvent
				HandleData(QUICEncryptionLevel, []byte) error
				ConnectionState() ConnectionState
			}
			endpoints := []quicEndpoint{client, server}
			for _, endpoint := range endpoints {
				if err := endpoint.Start(t.Context()); err != nil {
					t.Fatal(err)
				}
			}
			var complete, gotParams [2]bool
			for current, idle := 0, 0; idle < 2; {
				event := endpoints[current].NextEvent()
				if event.Kind == QUICNoEvent {
					idle++
					current = 1 - current
					continue
				}
				idle = 0
				switch event.Kind {
				case QUICWriteData:
					if err := endpoints[1-current].HandleData(event.Level, event.Data); err != nil {
						t.Fatal(err)
					}
				case QUICTransportParameters:
					gotParams[current] = true
				case QUICHandshakeDone:
					complete[current] = true
				case QUICSetReadSecret, QUICSetWriteSecret:
				default:
					t.Fatalf("unexpected QUIC event: %+v", event)
				}
			}
			for i, endpoint := range endpoints {
				state := endpoint.ConnectionState()
				if !complete[i] || !state.HandshakeComplete || state.Version != VersionTLS13 || state.NegotiatedProtocol != "h3" || !gotParams[i] {
					t.Errorf("endpoint %d: complete=%v, state=%+v, got transport parameters=%v", i, complete[i], state, gotParams[i])
				}
			}
			if !callbackCalled {
				t.Error("GetConfigForClient was not called")
			}
		})
	}
}

func TestUTLSMLDSAAndLocalCertificate(t *testing.T) {
	if fips140.Version() == "v1.0.0" {
		t.Skip("ML-DSA is unavailable in FIPS 140-3 module v1.0.0")
	}
	for _, tc := range []struct {
		scheme     SignatureScheme
		serverCert Certificate
		clientCert Certificate
	}{
		{MLDSA44, testMLDSA44Cert, testClientMLDSA44Cert},
		{MLDSA65, testMLDSA65Cert, testClientMLDSA65Cert},
		{MLDSA87, testMLDSA87Cert, testClientMLDSA87Cert},
	} {
		t.Run(tc.scheme.String(), func(t *testing.T) {
			clientConfig := testConfigClient.Clone()
			clientConfig.Certificates = []Certificate{tc.clientCert}
			serverConfig := testConfigServer.Clone()
			serverConfig.Certificates = []Certificate{tc.serverCert}
			serverConfig.ClientAuth = RequireAndVerifyClientCert

			serverState, clientState, err := testUtlsHandshake(t, clientConfig, serverConfig,
				go127ClientHelloSpec([]SignatureScheme{tc.scheme, ECDSAWithP256AndSHA256}))
			if err != nil {
				t.Fatalf("custom ML-DSA handshake: %v", err)
			}
			for _, state := range []ConnectionState{clientState, serverState} {
				if !state.HandshakeComplete || state.Version != VersionTLS13 {
					t.Fatalf("handshake did not complete with TLS 1.3: %+v", state)
				}
				if len(state.PeerCertificates) == 0 {
					t.Fatal("missing peer certificate")
				}
				if _, ok := state.PeerCertificates[0].PublicKey.(*mldsa.PublicKey); !ok {
					t.Errorf("peer public key = %T, want *mldsa.PublicKey", state.PeerCertificates[0].PublicKey)
				}
			}
			if !slices.EqualFunc(clientState.LocalCertificate, tc.clientCert.Certificate, bytes.Equal) {
				t.Error("UConn.ConnectionState.LocalCertificate does not match the sent client certificate")
			}
			if !slices.EqualFunc(serverState.LocalCertificate, tc.serverCert.Certificate, bytes.Equal) {
				t.Error("server ConnectionState.LocalCertificate does not match the sent server certificate")
			}
		})
	}
}

func TestUTLSMLKEM1024(t *testing.T) {
	for _, helloID := range []ClientHelloID{HelloGolang, HelloCustom} {
		for _, retry := range []bool{false, true} {
			name := helloID.Str() + "/Direct"
			if retry {
				name = helloID.Str() + "/HelloRetryRequest"
			}
			t.Run(name, func(t *testing.T) {
				clientConfig := testConfigClient.Clone()
				clientConfig.MinVersion = VersionTLS13
				clientConfig.CurvePreferences = []CurveID{MLKEM1024}
				initialGroup := MLKEM1024
				if retry {
					initialGroup = X25519
					clientConfig.CurvePreferences = []CurveID{X25519}
				}
				serverConfig := testConfigServer.Clone()
				serverConfig.CurvePreferences = []CurveID{MLKEM1024}
				serverConfig.SessionTicketsDisabled = true

				clientConn, serverConn := localPipe(t)
				defer clientConn.Close()
				defer serverConn.Close()
				client := UClient(clientConn, clientConfig, helloID)
				if helloID == HelloCustom {
					preset := go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256})
					for _, extension := range preset.Extensions {
						switch extension := extension.(type) {
						case *SupportedCurvesExtension:
							extension.Curves = []CurveID{initialGroup}
							if retry {
								extension.Curves = append(extension.Curves, MLKEM1024)
							}
						case *KeyShareExtension:
							extension.KeyShares = []KeyShare{{Group: initialGroup}}
						}
					}
					if err := client.ApplyPreset(preset); err != nil {
						t.Fatal(err)
					}
				}
				if err := client.BuildHandshakeState(); err != nil {
					t.Fatal(err)
				}
				if retry {
					// Go prefers ML-KEM to X25519. Advertise ML-KEM after building
					// the initial X25519 share to exercise the retry path explicitly.
					clientConfig.CurvePreferences = []CurveID{X25519, MLKEM1024}
					if helloID == HelloGolang {
						client.HandshakeState.Hello.SupportedCurves = append(client.HandshakeState.Hello.SupportedCurves, MLKEM1024)
					}
				}
				if shares := client.HandshakeState.Hello.KeyShares; len(shares) != 1 || shares[0].Group != initialGroup {
					t.Fatalf("initial key shares = %+v, want only %v", shares, initialGroup)
				}

				server := Server(serverConn, serverConfig)
				clientResult := make(chan error, 1)
				go func() { clientResult <- client.Handshake() }()
				serverErr := server.Handshake()
				if serverErr != nil {
					serverConn.Close()
				}
				clientErr := <-clientResult
				if clientErr != nil || serverErr != nil {
					t.Fatalf("MLKEM1024 handshake: client=%v, server=%v", clientErr, serverErr)
				}
				for _, state := range []ConnectionState{client.ConnectionState(), server.ConnectionState()} {
					if !state.HandshakeComplete || state.Version != VersionTLS13 || state.CurveID != MLKEM1024 || state.HelloRetryRequest != retry {
						t.Errorf("unexpected MLKEM1024 connection state: %+v", state)
					}
				}
			})
		}
	}
}

func TestUTLSPSKResumptionWithHelloRetryRequest(t *testing.T) {
	clientConfig := testConfigClient.Clone()
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	clientConfig.OmitEmptyPsk = true
	serverConfig := testConfigServer.Clone()
	serverConfig.CurvePreferences = []CurveID{CurveP256}

	for _, resume := range []bool{false, true} {
		preset := go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256})
		for _, extension := range preset.Extensions {
			if curves, ok := extension.(*SupportedCurvesExtension); ok {
				curves.Curves = []CurveID{X25519, CurveP256}
			}
		}
		preset.Extensions = append(preset.Extensions,
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&UtlsPreSharedKeyExtension{},
		)
		// The helper reads application data after the handshake, allowing the
		// first connection's NewSessionTicket to populate the shared cache.
		serverState, clientState, err := testUtlsHandshake(t, clientConfig, serverConfig, preset)
		if err != nil {
			t.Fatalf("resume=%v: handshake: %v", resume, err)
		}
		for _, state := range []ConnectionState{clientState, serverState} {
			if state.DidResume != resume || !state.HelloRetryRequest || state.CurveID != CurveP256 {
				t.Errorf("resume=%v: unexpected connection state: %+v", resume, state)
			}
		}
		if session, ok := clientConfig.ClientSessionCache.Get(clientConfig.ServerName); !ok || session == nil {
			t.Fatal("session ticket was not stored in the client cache")
		}
	}
}

func TestUTLSHelloGolangECHResumption(t *testing.T) {
	echKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	builder := cryptobyte.NewBuilder(nil)
	builder.AddUint16(extensionEncryptedClientHello)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddUint8(123)     // config_id
		builder.AddUint16(0x0020) // DHKEM(X25519, HKDF-SHA256)
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes(echKey.PublicKey().Bytes())
		})
		builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddUint16(0x0001) // HKDF-SHA256
			builder.AddUint16(0x0001) // AES-128-GCM
		})
		builder.AddUint8(32) // maximum_name_length
		builder.AddUint8LengthPrefixed(func(builder *cryptobyte.Builder) {
			builder.AddBytes([]byte("public.example"))
		})
		builder.AddUint16(0) // extensions
	})
	echConfig := builder.BytesOrPanic()
	builder = cryptobyte.NewBuilder(nil)
	builder.AddUint16LengthPrefixed(func(builder *cryptobyte.Builder) {
		builder.AddBytes(echConfig)
	})
	clientConfig := testConfigClient.Clone()
	clientConfig.EncryptedClientHelloConfigList = builder.BytesOrPanic()
	clientConfig.ClientSessionCache = NewLRUClientSessionCache(1)
	serverConfig := testConfigServer.Clone()
	serverConfig.EncryptedClientHelloKeys = []EncryptedClientHelloKey{{
		Config: echConfig, PrivateKey: echKey.Bytes(), SendAsRetry: true,
	}}

	for _, resume := range []bool{false, true} {
		clientConn, serverConn := localPipe(t)
		defer clientConn.Close()
		defer serverConn.Close()
		client := UClient(clientConn, clientConfig, HelloGolang)
		server := Server(serverConn, serverConfig)
		serverResult := make(chan error, 1)
		go func() {
			defer serverConn.Close()
			if err := server.Handshake(); err != nil {
				serverResult <- err
				return
			}
			_, err := io.WriteString(server, "ok")
			serverResult <- err
		}()
		clientErr := client.Handshake()
		if clientErr == nil {
			var applicationData [2]byte
			_, clientErr = io.ReadFull(client, applicationData[:])
			if clientErr == nil && string(applicationData[:]) != "ok" {
				clientErr = fmt.Errorf("unexpected application data: %q", applicationData)
			}
		} else {
			clientConn.Close()
		}
		serverErr := <-serverResult
		if clientErr != nil || serverErr != nil {
			t.Fatalf("ECH resume=%v: client=%v, server=%v", resume, clientErr, serverErr)
		}
		for _, state := range []ConnectionState{client.ConnectionState(), server.ConnectionState()} {
			if !state.ECHAccepted || state.DidResume != resume || state.ServerName != clientConfig.ServerName {
				t.Errorf("ECH resume=%v: unexpected connection state: %+v", resume, state)
			}
		}
		if session, ok := clientConfig.ClientSessionCache.Get(clientConfig.ServerName); !ok || session == nil {
			t.Fatal("ECH session ticket was not stored in the client cache")
		}
	}
}

func go127ClientHelloSpec(signatureSchemes []SignatureScheme) *ClientHelloSpec {
	return &ClientHelloSpec{
		CipherSuites: []uint16{TLS_AES_128_GCM_SHA256},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13}},
			&SupportedCurvesExtension{Curves: []CurveID{X25519}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: signatureSchemes},
			&KeyShareExtension{KeyShares: []KeyShare{{Group: X25519}}},
		},
	}
}

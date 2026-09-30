// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"
)

const utlsTestECHConfigsHex = "0045fe0d0041590020002092a01233db2218518ccbbbbc24df20686af417b37388de6460e94011974777090004000100010012636c6f7564666c6172652d6563682e636f6d0000"
const utlsTestCustomECHPSKError = "tls: PSK resumption with a custom ECH ClientHello is not supported"

func TestUTLSECHPreSharedKeyPrivacy(t *testing.T) {
	// This is the supported X25519 ECHConfigList used in ech_test.go. A
	// server private key is unnecessary when inspecting ClientHelloOuter.
	echConfigs, err := hex.DecodeString(utlsTestECHConfigsHex)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name       string
		realECH    bool
		populated  bool
		wantReject bool
	}{
		{name: "RealECHWithPSK", realECH: true, populated: true, wantReject: true},
		{name: "RealECHWithEmptyPSK", realECH: true},
		{name: "GREASEECHWithPSK", populated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{ServerName: "private.example", InsecureSkipVerify: true, OmitEmptyPsk: true}
			if tc.realECH {
				config.EncryptedClientHelloConfigList = echConfigs
			}
			client := UClient(nil, config, HelloChrome_120)
			if err := client.BuildHandshakeStateWithoutSession(); err != nil {
				t.Fatal(err)
			}

			label := []byte("private-session-ticket-visible-in-ech-outer")
			psk := &UtlsPreSharedKeyExtension{OmitEmptyPsk: true}
			if tc.populated {
				// Model an initialized extension after the session controller has
				// loaded a ticket, immediately before ClientHello serialization.
				psk.PreSharedKeyCommon = PreSharedKeyCommon{
					Session:    &SessionState{version: VersionTLS13, cipherSuite: TLS_AES_128_GCM_SHA256},
					Identities: []PskIdentity{{Label: label}},
					Binders:    [][]byte{make([]byte, 32)},
				}
			}
			client.Extensions = append(client.Extensions, psk)

			err := client.MarshalClientHello()
			if tc.wantReject {
				if err == nil {
					t.Fatalf("real ECH with PSK must fail explicitly until inner binders are supported; ticket exposed in outer: %v", bytes.Contains(client.HandshakeState.Hello.Raw, label))
				}
				if err.Error() != utlsTestCustomECHPSKError {
					t.Fatalf("expected explicit ECH/PSK error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			outer := new(clientHelloMsg)
			if !outer.unmarshal(client.HandshakeState.Hello.Raw) {
				t.Fatal("invalid marshaled ClientHello")
			}
			if len(outer.encryptedClientHello) == 0 {
				t.Fatal("missing ECH extension")
			}
			if tc.populated {
				if len(outer.pskIdentities) != 1 || !bytes.Equal(outer.pskIdentities[0].label, label) {
					t.Fatal("GREASE ECH removed the ordinary PSK identity")
				}
			} else if len(outer.pskIdentities) != 0 {
				t.Fatal("empty PSK extension was not omitted")
			}
		})
	}
}

func TestUTLSECHCachedSessionPrivacy(t *testing.T) {
	echConfigs, err := hex.DecodeString(utlsTestECHConfigsHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, realECH := range []bool{false, true} {
		name := "GREASEECH"
		if realECH {
			name = "RealECH"
		}
		t.Run(name, func(t *testing.T) {
			config := testConfigClient.Clone()
			config.ServerName = "private.example"
			config.InsecureSkipVerify = true
			config.ClientSessionCache = NewLRUClientSessionCache(1)
			config.OmitEmptyPsk = true
			if realECH {
				config.EncryptedClientHelloConfigList = echConfigs
			}
			label := []byte("cached-private-session-ticket")
			config.ClientSessionCache.Put(config.ServerName, &ClientSessionState{session: &SessionState{
				version:          VersionTLS13,
				cipherSuite:      TLS_AES_128_GCM_SHA256,
				createdAt:        uint64(config.time().Unix()),
				useBy:            uint64(config.time().Add(time.Hour).Unix()),
				secret:           bytes.Repeat([]byte{1}, 32),
				peerCertificates: []*x509.Certificate{testECDSAP256Cert.Leaf},
				ticket:           label,
			}})
			preset, err := UTLSIdToSpec(HelloChrome_120)
			if err != nil {
				t.Fatal(err)
			}
			preset.Extensions = append(preset.Extensions, &UtlsPreSharedKeyExtension{})
			client := UClient(nil, config, HelloCustom)
			if err := client.ApplyPreset(&preset); err != nil {
				t.Fatal(err)
			}
			err = client.BuildHandshakeState()
			if realECH {
				if err == nil || err.Error() != utlsTestCustomECHPSKError {
					t.Fatalf("cached session with real ECH must fail before patching binders, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			outer := new(clientHelloMsg)
			if !outer.unmarshal(client.HandshakeState.Hello.Raw) {
				t.Fatal("invalid GREASE ECH ClientHello")
			}
			if len(outer.pskIdentities) != 1 || !bytes.Equal(outer.pskIdentities[0].label, label) {
				t.Fatal("GREASE ECH did not load the cached session")
			}
			if len(outer.pskBinders) != 1 || len(outer.pskBinders[0]) != 32 || bytes.Equal(outer.pskBinders[0], make([]byte, 32)) {
				t.Fatal("GREASE ECH did not compute the cached session's binder")
			}
		})
	}
}

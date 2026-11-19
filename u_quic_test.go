// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"context"
	"errors"
	"testing"
	"time"
)

// newTestUQUICClient returns a UQUICConn for helloID, with a QUIC-capable preset for
// HelloCustom.
func newTestUQUICClient(t *testing.T, config *Config, helloID ClientHelloID) *UQUICConn {
	t.Helper()
	config.MinVersion = VersionTLS13
	config.NextProtos = []string{"h3"}
	client := UQUICClient(&QUICConfig{TLSConfig: config}, helloID)
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
	return client
}

// Like TestQUICCanceledWaitingForData, for UQUICConn: Close while the handshake waits for
// the server must return instead of deadlocking.
func TestUQUICCanceledWaitingForData(t *testing.T) {
	for _, helloID := range []ClientHelloID{HelloGolang, HelloCustom} {
		t.Run(helloID.Str(), func(t *testing.T) {
			client := newTestUQUICClient(t, testConfigClient.Clone(), helloID)
			if err := client.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			for client.NextEvent().Kind != QUICNoEvent {
			}
			closed := make(chan error, 1)
			go func() { closed <- client.Close() }()
			select {
			case err := <-closed:
				if !errors.Is(err, alertCloseNotify) {
					t.Errorf("Close() = %v, want alertCloseNotify", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close() deadlocked")
			}
		})
	}
}

// Like TestQUICHandshakeError, for UQUICConn: a failed handshake is reported once by
// NextEvent as a QUICErrorEvent.
func TestUQUICHandshakeError(t *testing.T) {
	for _, helloID := range []ClientHelloID{HelloGolang, HelloCustom} {
		t.Run(helloID.Str(), func(t *testing.T) {
			clientConfig := testConfigClient.Clone()
			clientConfig.InsecureSkipVerify = false
			clientConfig.ServerName = "name"
			client := newTestUQUICClient(t, clientConfig, helloID)
			defer client.Close()

			serverConfig := testConfigServer.Clone()
			serverConfig.MinVersion = VersionTLS13
			serverConfig.NextProtos = []string{"h3"}
			server := QUICServer(&QUICConfig{TLSConfig: serverConfig})
			defer server.Close()
			server.SetTransportParameters(nil)

			if err := client.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := server.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			var handshakeErr error
			for handshakeErr == nil {
				ev := client.NextEvent()
				if ev.Kind == QUICErrorEvent {
					t.Fatalf("QUICErrorEvent before the handshake failed: %v", ev.Err)
				}
				if ev.Kind == QUICWriteData {
					if err := server.HandleData(ev.Level, ev.Data); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if ev.Kind != QUICNoEvent {
					continue
				}
				progressed := false
				for sev := server.NextEvent(); sev.Kind != QUICNoEvent; sev = server.NextEvent() {
					if sev.Kind == QUICWriteData {
						progressed = true
						if err := client.HandleData(sev.Level, sev.Data); err != nil {
							handshakeErr = err
							break
						}
					}
				}
				if !progressed && handshakeErr == nil {
					t.Fatal("handshake stalled without an error")
				}
			}
			if !errors.Is(handshakeErr, AlertError(alertBadCertificate)) {
				t.Fatalf("handshake error %v, want alertBadCertificate", handshakeErr)
			}

			ev := client.NextEvent()
			if ev.Kind != QUICErrorEvent {
				t.Fatalf("NextEvent() = %v, want QUICErrorEvent", ev.Kind)
			}
			if !errors.Is(ev.Err, AlertError(alertBadCertificate)) {
				t.Errorf("QUICErrorEvent.Err = %v, want alertBadCertificate", ev.Err)
			}
			if ev := client.NextEvent(); ev.Kind != QUICNoEvent {
				t.Errorf("second NextEvent() = %v, want QUICNoEvent", ev.Kind)
			}
		})
	}
}

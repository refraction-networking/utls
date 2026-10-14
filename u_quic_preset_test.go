// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"sync"
	"testing"
)

func newUQUICPresetClient(t *testing.T) *UQUICConn {
	t.Helper()
	clientConfig := testConfigClient.Clone()
	clientConfig.NextProtos = []string{"h3"}
	client := UQUICClient(&QUICConfig{TLSConfig: clientConfig}, HelloCustom)
	preset := go127ClientHelloSpec([]SignatureScheme{ECDSAWithP256AndSHA256})
	preset.Extensions = append(preset.Extensions,
		&ALPNExtension{AlpnProtocols: []string{"h3"}},
		&QUICTransportParametersExtension{},
	)
	if err := client.ApplyPreset(preset); err != nil {
		t.Fatal(err)
	}
	return client
}

func newUQUICTestServer() *QUICConn {
	serverConfig := testConfigServer.Clone()
	serverConfig.NextProtos = []string{"h3"}
	return QUICServer(&QUICConfig{TLSConfig: serverConfig})
}

type uquicTestEndpoint interface {
	Start(context.Context) error
	NextEvent() QUICEvent
	HandleData(QUICEncryptionLevel, []byte) error
}

// runUQUICHandshake pumps events between the endpoints until both are idle
// or one fails, and returns the transport parameters each side received.
func runUQUICHandshake(ctx context.Context, client, server uquicTestEndpoint) (got [2][]byte, err error) {
	endpoints := []uquicTestEndpoint{client, server}
	for _, endpoint := range endpoints {
		if err := endpoint.Start(ctx); err != nil {
			return got, err
		}
	}
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
				return got, err
			}
		case QUICTransportParameters:
			got[current] = append([]byte{}, event.Data...)
		}
	}
	return got, nil
}

// SetTransportParameters must reach the ClientHello when a preset is applied:
// ApplyPreset clones the spec, so the extension the caller passed is no longer
// the one that is marshaled.
func TestUQUICPresetTransportParameters(t *testing.T) {
	params := []byte{0x04, 0x04, 0x80, 0x10, 0x00, 0x00} // initial_max_data
	client := newUQUICPresetClient(t)
	defer client.Close()
	client.SetTransportParameters(params)
	server := newUQUICTestServer()
	defer server.Close()
	server.SetTransportParameters(nil)

	got, err := runUQUICHandshake(t.Context(), client, server)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got[1], params) {
		t.Errorf("server received transport parameters %x, want %x", got[1], params)
	}
}

// Canceling the context concurrently with a handshake must not race with
// UQUICConn methods, as for QUICConn. See https://go.dev/issue/77274.
func TestUQUICContextCancelation(t *testing.T) {
	for range 20 {
		ctx, cancel := context.WithCancel(context.Background())
		client := newUQUICPresetClient(t)
		client.SetTransportParameters(nil)
		server := newUQUICTestServer()
		server.SetTransportParameters(nil)
		var wg sync.WaitGroup
		wg.Go(func() {
			_, _ = runUQUICHandshake(ctx, client, server)
			client.Close()
			server.Close()
		})
		wg.Go(cancel)
		wg.Wait()
	}
}

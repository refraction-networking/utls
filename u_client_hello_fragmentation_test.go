// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestWriteHandshakeRecordFragmentsClientHello(t *testing.T) {
	const serverName = "example.org"
	hello := testClientHelloWithServerName(serverName)
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}

	conn := &clientHelloFragmentationTestConn{}
	tlsConn := &Conn{
		conn:     conn,
		isClient: true,
		config:   &Config{FragmentClientHello: testClientHelloFragmentOffset},
	}

	n, err := tlsConn.writeHandshakeRecord(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
	}
	fragmentedData := testFragmentedClientHello(t, conn.writes)
	if !bytes.Equal(fragmentedData, data) {
		t.Fatal("fragment payloads do not reconstruct original ClientHello")
	}
	testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), true)
}

func TestWriteHandshakeRecordFragmentsClientHelloWithCustomOffset(t *testing.T) {
	hello := testClientHelloWithServerName("example.org")
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	split := len(data) / 2
	called := 0

	conn := &clientHelloFragmentationTestConn{}
	tlsConn := &Conn{
		conn:     conn,
		isClient: true,
		config: &Config{FragmentClientHello: func(clientHello []byte) int {
			called++
			if !bytes.Equal(clientHello, data) {
				t.Fatal("callback ClientHello does not match marshaled data")
			}
			return split
		}},
	}

	n, err := tlsConn.writeHandshakeRecord(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
	}
	if called != 1 {
		t.Fatalf("unexpected callback count: got %d, want 1", called)
	}
	if len(conn.writes) != 2 {
		t.Fatalf("unexpected write count: got %d, want 2", len(conn.writes))
	}
	payload1 := testTLSRecordPayload(t, conn.writes[0])
	payload2 := testTLSRecordPayload(t, conn.writes[1])
	if len(payload1) != split {
		t.Fatalf("unexpected first payload length: got %d, want %d", len(payload1), split)
	}
	fragmentedData := append(append([]byte{}, payload1...), payload2...)
	if !bytes.Equal(fragmentedData, data) {
		t.Fatal("fragment payloads do not reconstruct original ClientHello")
	}
	testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), true)
}

func TestWriteHandshakeRecordFragmentationFallsBackForInvalidOffsets(t *testing.T) {
	hello := testClientHelloWithServerName("example.org")
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}

	for _, offset := range []int{-1, 0, len(data), len(data) + 1} {
		t.Run(fmt.Sprintf("offset_%d", offset), func(t *testing.T) {
			called := 0
			conn := &clientHelloFragmentationTestConn{}
			tlsConn := &Conn{
				conn:     conn,
				isClient: true,
				config: &Config{FragmentClientHello: func([]byte) int {
					called++
					return offset
				}},
			}

			n, err := tlsConn.writeHandshakeRecord(hello, nil)
			if err != nil {
				t.Fatal(err)
			}
			if n != len(data) {
				t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
			}
			if called != 1 {
				t.Fatalf("unexpected callback count: got %d, want 1", called)
			}
			if len(conn.writes) != 1 {
				t.Fatalf("unexpected write count: got %d, want 1", len(conn.writes))
			}
			if payload := testTLSRecordPayload(t, conn.writes[0]); !bytes.Equal(payload, data) {
				t.Fatal("fallback payload does not match original ClientHello")
			}
			testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), false)
		})
	}
}

func TestWriteHandshakeRecordFragmentsHelloCustomClientHello(t *testing.T) {
	const serverName = "example.org"
	uconn, hello, data, conn := testUConnWithClientHello(t, serverName, []TLSExtension{&SNIExtension{}})

	n, err := uconn.writeHandshakeRecord(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
	}
	fragmentedData := testFragmentedClientHello(t, conn.writes)
	if !bytes.Equal(fragmentedData, data) {
		t.Fatal("fragment payloads do not reconstruct original ClientHello")
	}
}

func TestWriteHandshakeRecordFragmentsHelloGolangClientHello(t *testing.T) {
	const serverName = "example.org"
	conn := &clientHelloFragmentationTestConn{}
	uconn := UClient(conn, testClientHelloFragmentationConfig(serverName), HelloGolang)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Fatal(err)
	}

	hello := uconn.HandshakeState.Hello.getPrivatePtr()
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	n, err := uconn.writeHandshakeRecord(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
	}
	fragmentedData := testFragmentedClientHello(t, conn.writes)
	if !bytes.Equal(fragmentedData, data) {
		t.Fatal("fragment payloads do not reconstruct original ClientHello")
	}
}

func TestWriteHandshakeRecordFragmentsStandardClientHello(t *testing.T) {
	const serverName = "example.org"
	conn := &clientHelloFragmentationTestConn{}
	tlsConn := Client(conn, testClientHelloFragmentationConfig(serverName))
	hello, _, _, err := tlsConn.makeClientHello()
	if err != nil {
		t.Fatal(err)
	}
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}

	n, err := tlsConn.writeHandshakeRecord(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
	}
	fragmentedData := testFragmentedClientHello(t, conn.writes)
	if !bytes.Equal(fragmentedData, data) {
		t.Fatal("fragment payloads do not reconstruct original ClientHello")
	}
}

func TestClientHelloFragmentationHandshake(t *testing.T) {
	const serverName = "example.org"
	tests := []struct {
		name                string
		version             uint16
		fragmentClientHello ClientHelloFragFunc
		newClient           func(net.Conn, *Config) clientHelloFragmentationHandshakeClient
	}{
		{
			name:    "StandardTLS12",
			version: VersionTLS12,
			newClient: func(conn net.Conn, config *Config) clientHelloFragmentationHandshakeClient {
				return Client(conn, config)
			},
		},
		{
			name:    "StandardTLS13",
			version: VersionTLS13,
			newClient: func(conn net.Conn, config *Config) clientHelloFragmentationHandshakeClient {
				return Client(conn, config)
			},
		},
		{
			name:    "UTLSHelloGolangTLS12",
			version: VersionTLS12,
			newClient: func(conn net.Conn, config *Config) clientHelloFragmentationHandshakeClient {
				return UClient(conn, config, HelloGolang)
			},
		},
		{
			name:                "UTLSChrome120TLS13",
			version:             VersionTLS13,
			fragmentClientHello: testClientHelloSNIFragmentOffset,
			newClient: func(conn net.Conn, config *Config) clientHelloFragmentationHandshakeClient {
				return UClient(conn, config, HelloChrome_120)
			},
		},
		{
			name:    "UTLSFirefox120TLS13",
			version: VersionTLS13,
			newClient: func(conn net.Conn, config *Config) clientHelloFragmentationHandshakeClient {
				return UClient(conn, config, HelloFirefox_120)
			},
		},
		{
			name:    "UTLSSafari16TLS13",
			version: VersionTLS13,
			newClient: func(conn net.Conn, config *Config) clientHelloFragmentationHandshakeClient {
				return UClient(conn, config, HelloSafari_16_0)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientConfig := testConfig.Clone()
			clientConfig.ServerName = serverName
			clientConfig.InsecureSkipVerify = true
			clientConfig.MinVersion = tt.version
			clientConfig.MaxVersion = tt.version
			fragmentClientHello := tt.fragmentClientHello
			if fragmentClientHello == nil {
				fragmentClientHello = testClientHelloFragmentOffset
			}
			clientConfig.FragmentClientHello = fragmentClientHello

			serverConfig := testConfig.Clone()
			serverConfig.MinVersion = tt.version
			serverConfig.MaxVersion = tt.version

			clientConn, serverConn := localPipe(t)
			recordingClientConn := &recordingConn{Conn: clientConn}
			client := tt.newClient(recordingClientConn, clientConfig)
			server := Server(serverConn, serverConfig)
			defer client.Close()
			defer server.Close()

			serverErr := make(chan error, 1)
			go func() {
				serverErr <- server.Handshake()
			}()

			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			testClientHelloFragmentedMetric(t, client.ConnectionMetrics(), true)

			records := testTLSRecords(t, testFirstRecordedClientFlow(t, recordingClientConn))
			testFragmentedClientHelloAtOffset(t, records, fragmentClientHello)
		})
	}
}

func TestClientHelloFragmentationHelloRetryRequest(t *testing.T) {
	const serverName = "example.org"

	tests := []struct {
		name                string
		fallbackSecondHello bool
		wantRecordCounts    []int
	}{
		{
			name:             "fragment both ClientHellos",
			wantRecordCounts: []int{2, 2},
		},
		{
			name:                "fallback for second ClientHello",
			fallbackSecondHello: true,
			wantRecordCounts:    []int{2, 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			callbackCalls := 0

			clientConfig := testConfig.Clone()
			clientConfig.ServerName = serverName
			clientConfig.InsecureSkipVerify = true
			clientConfig.MinVersion = VersionTLS13
			clientConfig.MaxVersion = VersionTLS13
			clientConfig.CurvePreferences = []CurveID{X25519, CurveP256}
			clientConfig.FragmentClientHello = func(clientHello []byte) int {
				callbackCalls++
				if tt.fallbackSecondHello && callbackCalls == 2 {
					return 0
				}
				return testClientHelloFragmentOffset(clientHello)
			}

			serverConfig := testConfig.Clone()
			serverConfig.MinVersion = VersionTLS13
			serverConfig.MaxVersion = VersionTLS13
			serverConfig.CurvePreferences = []CurveID{CurveP256}

			clientConn, serverConn := localPipe(t)
			recordingClientConn := &recordingConn{Conn: clientConn}
			client := Client(recordingClientConn, clientConfig)
			server := Server(serverConn, serverConfig)
			defer client.Close()
			defer server.Close()

			serverErr := make(chan error, 1)
			go func() {
				serverErr <- server.Handshake()
			}()

			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if err := <-serverErr; err != nil {
				t.Fatal(err)
			}
			if !client.ConnectionState().HelloRetryRequest {
				t.Fatal("expected HelloRetryRequest")
			}

			clientHellos := testRecordedClientHellos(t, recordingClientConn)
			if len(clientHellos) != len(tt.wantRecordCounts) {
				t.Fatalf("unexpected ClientHello count: got %d, want %d",
					len(clientHellos), len(tt.wantRecordCounts))
			}
			for i, wantRecordCount := range tt.wantRecordCounts {
				if len(clientHellos[i]) != wantRecordCount {
					t.Fatalf("ClientHello %d record count: got %d, want %d",
						i+1, len(clientHellos[i]), wantRecordCount)
				}
				if wantRecordCount == 2 {
					testFragmentedClientHello(t, clientHellos[i])
				}
			}
			if callbackCalls != 2 {
				t.Fatalf("unexpected callback count: got %d, want 2", callbackCalls)
			}
			testClientHelloFragmentedMetric(t, client.ConnectionMetrics(), true)
		})
	}
}

func TestClientHelloFragmentationHandshakeFallback(t *testing.T) {
	clientConfig := testConfig.Clone()
	clientConfig.ServerName = ""
	clientConfig.InsecureSkipVerify = true
	clientConfig.MinVersion = VersionTLS12
	clientConfig.MaxVersion = VersionTLS12
	clientConfig.FragmentClientHello = func([]byte) int { return 0 }

	serverConfig := testConfig.Clone()
	serverConfig.MinVersion = VersionTLS12
	serverConfig.MaxVersion = VersionTLS12

	clientConn, serverConn := localPipe(t)
	recordingClientConn := &recordingConn{Conn: clientConn}
	client := Client(recordingClientConn, clientConfig)
	server := Server(serverConn, serverConfig)
	defer client.Close()
	defer server.Close()

	serverErr := make(chan error, 1)
	go func() {
		serverErr <- server.Handshake()
	}()

	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
	testClientHelloFragmentedMetric(t, client.ConnectionMetrics(), false)

	records := testTLSRecords(t, testFirstRecordedClientFlow(t, recordingClientConn))
	if len(records) != 1 {
		t.Fatalf("unexpected ClientHello record count: got %d, want 1", len(records))
	}
	if payload := testTLSRecordPayload(t, records[0]); len(payload) == 0 || payload[0] != typeClientHello {
		t.Fatalf("unexpected first handshake payload: %x", payload)
	}
}

func TestWriteHandshakeRecordDoesNotFragmentWithECHConfig(t *testing.T) {
	const serverName = "example.org"
	hello := testClientHelloWithServerName(serverName)
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	conn := &clientHelloFragmentationTestConn{}
	tlsConn := &Conn{
		conn:     conn,
		isClient: true,
		config: &Config{
			EncryptedClientHelloConfigList: []byte{1},
			FragmentClientHello:            testClientHelloFragmentOffset,
		},
	}

	n, err := tlsConn.writeHandshakeRecord(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
	}
	if len(conn.writes) != 1 {
		t.Fatalf("unexpected write count: got %d, want 1", len(conn.writes))
	}
	if payload := testTLSRecordPayload(t, conn.writes[0]); !bytes.Equal(payload, data) {
		t.Fatal("ECH fallback payload does not match original ClientHello")
	}
	testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), false)
}

func TestQUICClientHelloFragmentationIsIgnored(t *testing.T) {
	clientConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	clientConfig.TLSConfig.MinVersion = VersionTLS13
	clientConfig.TLSConfig.ServerName = "example.go.dev"
	clientConfig.TLSConfig.FragmentClientHello = testClientHelloFragmentOffset

	serverConfig := &QUICConfig{TLSConfig: testConfig.Clone()}
	serverConfig.TLSConfig.MinVersion = VersionTLS13

	cli := newTestQUICClient(t, clientConfig)
	cli.conn.SetTransportParameters(nil)
	srv := newTestQUICServer(t, serverConfig)
	srv.conn.SetTransportParameters(nil)

	if err := runTestQUICConnection(context.Background(), cli, srv, nil); err != nil {
		t.Fatalf("error during connection handshake: %v", err)
	}
	testClientHelloFragmentedMetric(t, cli.conn.conn.ConnectionMetrics(), false)
}

func TestWriteHandshakeRecordDoesNotFragmentWhenDisabled(t *testing.T) {
	hello := testClientHelloWithServerName("example.org")
	conn := &clientHelloFragmentationTestConn{}
	tlsConn := &Conn{
		conn:     conn,
		isClient: true,
		config:   &Config{},
	}

	if _, err := tlsConn.writeHandshakeRecord(hello, nil); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("unexpected write count: got %d, want 1", len(conn.writes))
	}
	testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), false)
}

func TestWriteHandshakeRecordFragmentsInitialHandshakeClientHellos(t *testing.T) {
	hello := testClientHelloWithServerName("example.org")
	called := 0
	conn := &clientHelloFragmentationTestConn{}
	tlsConn := &Conn{
		conn:     conn,
		isClient: true,
		config: &Config{FragmentClientHello: func(clientHello []byte) int {
			called++
			return testClientHelloFragmentOffset(clientHello)
		}},
	}

	if _, err := tlsConn.writeHandshakeRecord(hello, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tlsConn.writeHandshakeRecord(hello, nil); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 4 {
		t.Fatalf("unexpected write count: got %d, want 4", len(conn.writes))
	}
	if called != 2 {
		t.Fatalf("unexpected callback count: got %d, want 2", called)
	}
	testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), true)
}

func TestWriteHandshakeRecordDoesNotFragmentAfterInitialHandshake(t *testing.T) {
	hello := testClientHelloWithServerName("example.org")
	called := 0
	conn := &clientHelloFragmentationTestConn{}
	tlsConn := &Conn{
		conn:       conn,
		isClient:   true,
		handshakes: 1,
		config: &Config{FragmentClientHello: func(clientHello []byte) int {
			called++
			return testClientHelloFragmentOffset(clientHello)
		}},
	}

	if _, err := tlsConn.writeHandshakeRecord(hello, nil); err != nil {
		t.Fatal(err)
	}
	if len(conn.writes) != 1 {
		t.Fatalf("unexpected write count: got %d, want 1", len(conn.writes))
	}
	if called != 0 {
		t.Fatalf("unexpected callback count: got %d, want 0", called)
	}
	testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), false)
}

func TestWriteHandshakeRecordFragmentationFallsBack(t *testing.T) {
	hello := testClientHelloWithServerName("example.org")
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}
	conn := &clientHelloFragmentationTestConn{}
	tlsConn := &Conn{
		conn:     conn,
		isClient: true,
		config:   &Config{FragmentClientHello: func([]byte) int { return 0 }},
	}

	n, err := tlsConn.writeHandshakeRecord(hello, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("unexpected write count: got %d, want %d", n, len(data))
	}
	if len(conn.writes) != 1 {
		t.Fatalf("unexpected write count: got %d, want 1", len(conn.writes))
	}
	if payload := testTLSRecordPayload(t, conn.writes[0]); !bytes.Equal(payload, data) {
		t.Fatal("fallback payload does not match original ClientHello")
	}
	testClientHelloFragmentedMetric(t, tlsConn.ConnectionMetrics(), false)
}

func testClientHelloWithServerName(serverName string) *clientHelloMsg {
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}

	return &clientHelloMsg{
		vers:               VersionTLS12,
		random:             random,
		cipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		compressionMethods: []uint8{compressionNone},
		serverName:         serverName,
	}
}

func testClientHelloFragmentationConfig(serverName string) *Config {
	return &Config{
		ServerName:          serverName,
		InsecureSkipVerify:  true,
		Rand:                &zeroSource{},
		MinVersion:          VersionTLS12,
		MaxVersion:          VersionTLS12,
		FragmentClientHello: testClientHelloFragmentOffset,
	}
}

func testUConnWithClientHello(t *testing.T, serverName string, extensions []TLSExtension) (*UConn, *clientHelloMsg, []byte, *clientHelloFragmentationTestConn) {
	t.Helper()

	conn := &clientHelloFragmentationTestConn{}
	uconn := UClient(conn, testClientHelloFragmentationConfig(serverName), HelloCustom)
	spec := &ClientHelloSpec{
		TLSVersMin:         VersionTLS12,
		TLSVersMax:         VersionTLS12,
		CipherSuites:       []uint16{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions:         extensions,
	}
	if err := uconn.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	if err := uconn.ApplyConfig(); err != nil {
		t.Fatal(err)
	}
	if err := uconn.MarshalClientHello(); err != nil {
		t.Fatal(err)
	}

	hello := uconn.HandshakeState.Hello.getPrivatePtr()
	data, err := hello.marshal()
	if err != nil {
		t.Fatal(err)
	}

	return uconn, hello, data, conn
}

func testTLSRecordPayload(t *testing.T, record []byte) []byte {
	t.Helper()
	if len(record) < recordHeaderLen {
		t.Fatalf("record too short: %d", len(record))
	}
	if record[0] != byte(recordTypeHandshake) {
		t.Fatalf("unexpected record type: got %d, want %d", record[0], recordTypeHandshake)
	}
	payloadLen := int(record[3])<<8 | int(record[4])
	if payloadLen != len(record)-recordHeaderLen {
		t.Fatalf("unexpected record length: got %d, want %d", payloadLen, len(record)-recordHeaderLen)
	}
	return record[recordHeaderLen:]
}

func testClientHelloFragmentOffset(clientHello []byte) int {
	if len(clientHello) < 2 {
		return 0
	}
	return len(clientHello) / 2
}

func testClientHelloSNIFragmentOffset(clientHello []byte) int {
	const serverNamePrefix = "example"
	serverNameOffset := bytes.Index(clientHello, []byte("example.org"))
	if serverNameOffset < 0 {
		return 0
	}
	return serverNameOffset + len(serverNamePrefix)
}

func testFragmentedClientHello(t *testing.T, writes [][]byte) []byte {
	return testFragmentedClientHelloAtOffset(t, writes, testClientHelloFragmentOffset)
}

func testFragmentedClientHelloAtOffset(t *testing.T, writes [][]byte, fragmentOffset ClientHelloFragFunc) []byte {
	t.Helper()
	if len(writes) != 2 {
		t.Fatalf("unexpected write count: got %d, want 2", len(writes))
	}

	payload1 := testTLSRecordPayload(t, writes[0])
	payload2 := testTLSRecordPayload(t, writes[1])
	data := append(append([]byte{}, payload1...), payload2...)
	split := fragmentOffset(data)
	if split != len(payload1) {
		t.Fatalf("unexpected split offset: got %d, want %d", len(payload1), split)
	}
	return data
}

type clientHelloFragmentationHandshakeClient interface {
	Handshake() error
	Close() error
	ConnectionMetrics() ConnectionMetrics
}

func testClientHelloFragmentedMetric(t *testing.T, metrics ConnectionMetrics, fragmented bool) {
	t.Helper()
	if metrics.ClientHelloFragmented != fragmented {
		t.Fatalf("unexpected ClientHelloFragmented metric: got %t, want %t",
			metrics.ClientHelloFragmented, fragmented)
	}
}

func testFirstRecordedClientFlow(t *testing.T, conn *recordingConn) []byte {
	t.Helper()

	conn.Lock()
	defer conn.Unlock()
	if len(conn.flows) == 0 {
		t.Fatal("no recorded TLS flows")
	}
	return bytes.Clone(conn.flows[0])
}

func testRecordedClientHellos(t *testing.T, conn *recordingConn) [][][]byte {
	t.Helper()

	conn.Lock()
	flows := make([][]byte, len(conn.flows))
	for i, flow := range conn.flows {
		flows[i] = bytes.Clone(flow)
	}
	conn.Unlock()

	var clientHellos [][][]byte
	for i := 0; i < len(flows); i += 2 {
		records := testTLSRecords(t, flows[i])
		for j := 0; j < len(records); j++ {
			if records[j][0] != byte(recordTypeHandshake) {
				continue
			}
			payload := testTLSRecordPayload(t, records[j])
			if len(payload) == 0 || payload[0] != typeClientHello {
				continue
			}
			if len(payload) < 4 {
				t.Fatalf("ClientHello record too short: %d", len(payload))
			}

			want := 4 + (int(payload[1]) << 16) + (int(payload[2]) << 8) + int(payload[3])
			group := [][]byte{records[j]}
			data := bytes.Clone(payload)
			for len(data) < want && j+1 < len(records) {
				j++
				if records[j][0] != byte(recordTypeHandshake) {
					t.Fatalf("ClientHello continuation record has type %d, want %d", records[j][0], recordTypeHandshake)
				}
				payload = testTLSRecordPayload(t, records[j])
				data = append(data, payload...)
				group = append(group, records[j])
			}
			if len(data) != want {
				t.Fatalf("reassembled ClientHello length: got %d, want %d", len(data), want)
			}
			clientHellos = append(clientHellos, group)
		}
	}

	return clientHellos
}

func testTLSRecords(t *testing.T, flow []byte) [][]byte {
	t.Helper()

	var records [][]byte
	for len(flow) > 0 {
		if len(flow) < recordHeaderLen {
			t.Fatalf("TLS flow has partial record header: %d bytes", len(flow))
		}
		payloadLen := int(flow[3])<<8 | int(flow[4])
		recordLen := recordHeaderLen + payloadLen
		if len(flow) < recordLen {
			t.Fatalf("TLS flow has partial record: got %d bytes, want %d", len(flow), recordLen)
		}
		records = append(records, bytes.Clone(flow[:recordLen]))
		flow = flow[recordLen:]
	}
	return records
}

type clientHelloFragmentationTestConn struct {
	writes [][]byte
}

func (c *clientHelloFragmentationTestConn) Read([]byte) (int, error) {
	return 0, errors.New("read not supported")
}

func (c *clientHelloFragmentationTestConn) Write(b []byte) (int, error) {
	c.writes = append(c.writes, bytes.Clone(b))
	return len(b), nil
}

func (c *clientHelloFragmentationTestConn) Close() error { return nil }

func (c *clientHelloFragmentationTestConn) LocalAddr() net.Addr { return nil }

func (c *clientHelloFragmentationTestConn) RemoteAddr() net.Addr { return nil }

func (c *clientHelloFragmentationTestConn) SetDeadline(time.Time) error { return nil }

func (c *clientHelloFragmentationTestConn) SetReadDeadline(time.Time) error { return nil }

func (c *clientHelloFragmentationTestConn) SetWriteDeadline(time.Time) error { return nil }

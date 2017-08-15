// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

/*
TODO:
Reuse examples in tests?
Add tests for randomized and no parrot
Add session ticket tests
Add set client random tests
*/

func TestUTLSMarshalNoOp(t *testing.T) {
	// we rely on
	str := "We rely on clientHelloMsg.marshal() not doing anything if clientHelloMsg.raw is set"
	cHello, err := makeClientHello(getUTLSTestConfig())
	if err != nil {
		t.Errorf("Got error: %s; expected to succeed", err)
	}
	cHello.raw = []byte(str)
	marshalledHello := cHello.marshal()
	if strings.Compare(string(marshalledHello), str) != 0 {
		t.Errorf("clientHelloMsg.marshal() is not NOOP! Expected to get: %s, got: %s", str, string(marshalledHello))
	}
}

func runUTLSClientTestForVersion(t *testing.T, template *clientTest, prefix, option string, helloID ClientHelloID) {
	test := *template
	test.name = prefix + test.name
	if len(test.command) == 0 {
		test.command = defaultClientCommand
	}
	test.command = append([]string(nil), test.command...)
	test.command = append(test.command, option)
	test.runUTLS(t, *update, helloID)
}

func runUTLSClientTestTLS12(t *testing.T, template *clientTest, helloID ClientHelloID) {
	runUTLSClientTestForVersion(t, template, "TLSv12-", "-tls1_2", helloID)
}

func (test *clientTest) runUTLS(t *testing.T, write bool, helloID ClientHelloID) {
	checkOpenSSLVersion(t)

	var clientConn, serverConn net.Conn
	var recordingConn *recordingConn
	var childProcess *exec.Cmd
	var stdin opensslInput
	var stdout *opensslOutputSink

	if write {
		var err error
		recordingConn, childProcess, stdin, stdout, err = test.connFromCommand()
		if err != nil {
			t.Fatalf("Failed to start subcommand: %s", err)
		}
		clientConn = recordingConn
	} else {
		clientConn, serverConn = net.Pipe()
	}

	config := test.config
	if config == nil {
		t.Error("Explicit config is mandatory")
		return
	}
	client := UClient(clientConn, config, helloID)

	doneChan := make(chan bool)
	go func() {
		defer func() { doneChan <- true }()
		defer clientConn.Close()
		defer client.Close()

		err := client.Handshake()
		if err != nil {
			t.Errorf("Client.Handshake() failed: %s", err)
			return
		}

		if _, err := client.Write([]byte("hello\n")); err != nil {
			t.Errorf("Client.Write failed: %s", err)
			return
		}

		for i := 1; i <= test.numRenegotiations; i++ {
			// The initial handshake will generate a
			// handshakeComplete signal which needs to be quashed.
			if i == 1 && write {
				<-stdout.handshakeComplete
			}

			// OpenSSL will try to interleave application data and
			// a renegotiation if we send both concurrently.
			// Therefore: ask OpensSSL to start a renegotiation, run
			// a goroutine to call client.Read and thus process the
			// renegotiation request, watch for OpenSSL's stdout to
			// indicate that the handshake is complete and,
			// finally, have OpenSSL write something to cause
			// client.Read to complete.
			if write {
				stdin <- opensslRenegotiate
			}

			signalChan := make(chan struct{})

			go func() {
				defer func() { signalChan <- struct{}{} }()

				buf := make([]byte, 256)
				n, err := client.Read(buf)

				if test.checkRenegotiationError != nil {
					newErr := test.checkRenegotiationError(i, err)
					if err != nil && newErr == nil {
						return
					}
					err = newErr
				}

				if err != nil {
					t.Errorf("Client.Read failed after renegotiation #%d: %s", i, err)
					return
				}

				buf = buf[:n]
				if !bytes.Equal([]byte(opensslSentinel), buf) {
					t.Errorf("Client.Read returned %q, but wanted %q", string(buf), opensslSentinel)
				}

				if expected := i + 1; client.handshakes != expected {
					t.Errorf("client should have recorded %d handshakes, but believes that %d have occurred", expected, client.handshakes)
				}
			}()

			if write && test.renegotiationExpectedToFail != i {
				<-stdout.handshakeComplete
				stdin <- opensslSendSentinel
			}
			<-signalChan
		}

		if test.validate != nil {
			if err := test.validate(client.ConnectionState()); err != nil {
				t.Errorf("validate callback returned error: %s", err)
			}
		}
	}()

	if !write {
		flows, err := test.loadData()
		if err != nil {
			t.Fatalf("%s: failed to load data from %s: %v", test.name, test.dataPath(), err)
		}
		for i, b := range flows {
			if i%2 == 1 {
				serverConn.Write(b)
				continue
			}
			bb := make([]byte, len(b))
			_, err := io.ReadFull(serverConn, bb)
			if err != nil {
				t.Fatalf("%s #%d: %s", test.name, i, err)
			}
			if !bytes.Equal(b, bb) {
				t.Fatalf("%s #%d: mismatch on read: got:%x want:%x", test.name, i, bb, b)
			}
		}
		serverConn.Close()
	}

	<-doneChan

	if write {
		path := test.dataPath()
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			t.Fatalf("Failed to create output file: %s", err)
		}
		defer out.Close()
		recordingConn.Close()
		close(stdin)
		childProcess.Process.Kill()
		childProcess.Wait()
		if len(recordingConn.flows) < 3 {
			os.Stdout.Write(childProcess.Stdout.(*opensslOutputSink).all)
			t.Fatalf("Client connection didn't work")
		}
		recordingConn.WriteTo(out)
		fmt.Printf("Wrote %s\n", path)
	}
}

func TestUTLSHandshakeClientParrotAndroid_5_1(t *testing.T) {
	helloID := HelloAndroid_5_1_Browser

	// As this package sometimes has to modify global vars cipherSuites and supportedSignatureAlgorithms,
	// we'll back them up and restore after running the tests.
	supportedSignatureAlgorithmsBackup := make([]signatureAndHash, len(supportedSignatureAlgorithms))
	copy(supportedSignatureAlgorithmsBackup, supportedSignatureAlgorithms)
	defer func() {
		supportedSignatureAlgorithms = supportedSignatureAlgorithmsBackup
	}()

	// Android 5.1 offers old cipher ids for these, but current versions of OpenSSL no longer recognize old ids
	// testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, helloID)
	// testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, helloID)

	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t, helloID)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, helloID)
}

// Enable whenever EMS is implemented
func disabledtestUTLSHandshakeClientParrotAndroid_6_0(t *testing.T) {
	helloID := HelloAndroid_6_0_Browser

	// As this package sometimes has to modify global vars cipherSuites and supportedSignatureAlgorithms,
	// we'll back them up and restore after running the tests.
	supportedSignatureAlgorithmsBackup := make([]signatureAndHash, len(supportedSignatureAlgorithms))
	copy(supportedSignatureAlgorithmsBackup, supportedSignatureAlgorithms)
	defer func() {
		supportedSignatureAlgorithms = supportedSignatureAlgorithmsBackup
	}()

	// Android 6.0 offers old cipher ids for these, but current versions of OpenSSL no longer recognize old ids
	// testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, helloID)
	// testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, helloID)

	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, helloID)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, helloID)
}

// Enable whenever EMS is implemented
func disabledtestUTLSHandshakeClientParrotChrome_58(t *testing.T) {
	helloID := HelloChrome_58

	// As this package sometimes has to modify global vars cipherSuites and supportedSignatureAlgorithms,
	// we'll back them up and restore after running the tests.
	supportedSignatureAlgorithmsBackup := make([]signatureAndHash, len(supportedSignatureAlgorithms))
	copy(supportedSignatureAlgorithmsBackup, supportedSignatureAlgorithms)
	defer func() {
		supportedSignatureAlgorithms = supportedSignatureAlgorithmsBackup
	}()

	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t, helloID)

	testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, helloID)

	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, helloID)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, helloID)
}

func getUTLSTestConfig() *Config {
	testUTLSConfig := &Config{
		Time:               func() time.Time { return time.Unix(0, 0) },
		Rand:               zeroSource{},
		InsecureSkipVerify: true,
		MinVersion:         VersionSSL30,
		MaxVersion:         VersionTLS12,
		CipherSuites:       allCipherSuites(),
	}
	return testUTLSConfig
}

func testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-RSA-AES128-SHA"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-RSA-AES256-SHA"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-ECDSA-AES128-SHA"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		cert:    testECDSACertificate,
		key:     testECDSAPrivateKey,
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-ECDSA-AES256-SHA"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		cert:    testECDSACertificate,
		key:     testECDSAPrivateKey,
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	opensslCipherName := "AES128-GCM-SHA256"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-ECDSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		cert:    testECDSACertificate,
		key:     testECDSAPrivateKey,
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-ECDSA-AES256-GCM-SHA256"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		cert:    testECDSACertificate,
		key:     testECDSAPrivateKey,
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	config.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}
	opensslCipherName := "ECDHE-RSA-CHACHA20-POLY1305"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

func testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t *testing.T, helloID ClientHelloID) {
	config := getUTLSTestConfig()
	config.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305}
	opensslCipherName := "ECDHE-ECDSA-CHACHA20-POLY1305"
	test := &clientTest{
		name:    "UTLS-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
		cert:    testECDSACertificate,
		key:     testECDSAPrivateKey,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

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

func TestUTLSMarshalNoOp(t *testing.T) {
	str := "We rely on clientHelloMsg.marshal() not doing anything if clientHelloMsg.raw is set"
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "foobar"}, HelloGolang)
	msg, _, err := uconn.makeClientHello()
	if err != nil {
		t.Errorf("Got error: %s; expected to succeed", err)
	}
	msg.raw = []byte(str)
	marshalledHello := msg.marshal()
	if strings.Compare(string(marshalledHello), str) != 0 {
		t.Errorf("clientHelloMsg.marshal() is not NOOP! Expected to get: %s, got: %s", str, string(marshalledHello))
	}
}

func TestUTLSHandshakeClientParrotGolang(t *testing.T) {
	helloID := HelloGolang

	testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, helloID)

	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t, helloID)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, helloID)
}

func TestUTLSHandshakeClientParrotChrome_58(t *testing.T) {
	helloID := HelloChrome_58
	// TODO: EC tests below are disabled because latest version of reference OpenSSL doesn't support p256 nor p384
	// nor X25519 and I can't find configuration flag to enable it. Therefore I can't record replays.

	//testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, helloID)
	//testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t, helloID)

	//testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, helloID)

	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, helloID)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, helloID)
}

func TestUTLSHandshakeClientParrotFirefox_55(t *testing.T) {
	helloID := HelloFirefox_55

	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, helloID)

	testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, helloID)

	//testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t, helloID) TODO: enable when OpenSSL supports it
	testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t, helloID)

	testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t, helloID)

	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, helloID)
	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, helloID)
}

func TestUTLSHandshakeClientParrotChrome_58_setclienthello(t *testing.T) {
	helloID := HelloChrome_58
	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:    "UTLS-setclienthello-" + opensslCipherName + "-" + helloID.Str(),
		command: []string{"openssl", "s_server", "-cipher", opensslCipherName},
		config:  config,
	}

	runUTLSClientTestTLS12(t, test, helloID)
}

/*
*
 HELPER FUNCTIONS BELOW
*
*/

func getUTLSTestConfig() *Config {
	testUTLSConfig := &Config{
		Time: func() time.Time {
			return time.Unix(0, 0)
		},
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
		clientConn, serverConn = localPipe(t)
	}

	config := test.config
	if config == nil {
		t.Error("Explicit config is mandatory")
		return
	}
	client := UClient(clientConn, config, helloID)
	if strings.HasPrefix(test.name, "TLSv12-UTLS-setclienthello-") {
		err := client.BuildHandshakeState()
		if err != nil {
			t.Errorf("Client.BuildHandshakeState() failed: %s", err)
			return
		}
		// TODO: fix this name hack if we ever decide to use non-standard testing object
		err = client.SetClientRandom([]byte("Custom ClientRandom h^xbw8bf0sn3"))
		if err != nil {
			t.Errorf("Client.SetClientRandom() failed: %s", err)
			return
		}
	}

	doneChan := make(chan bool)
	go func() {
		defer func() {
			// Give time to the send buffer to drain, to avoid the kernel
			// sending a RST and cutting off the flow. See Issue 18701.
			time.Sleep(10 * time.Millisecond)
			client.Close()
			clientConn.Close()
			doneChan <- true
		}()

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
				defer close(signalChan)

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

		if test.sendKeyUpdate {
			if write {
				<-stdout.handshakeComplete
				stdin <- opensslKeyUpdate
			}

			doneRead := make(chan struct{})

			go func() {
				defer close(doneRead)

				buf := make([]byte, 256)
				n, err := client.Read(buf)

				if err != nil {
					t.Errorf("Client.Read failed after KeyUpdate: %s", err)
					return
				}

				buf = buf[:n]
				if !bytes.Equal([]byte(opensslSentinel), buf) {
					t.Errorf("Client.Read returned %q, but wanted %q", string(buf), opensslSentinel)
				}
			}()

			if write {
				// There's no real reason to wait for the client KeyUpdate to
				// send data with the new server keys, except that s_server
				// drops writes if they are sent at the wrong time.
				<-stdout.readKeyUpdate
				stdin <- opensslSendSentinel
			}
			<-doneRead

			if _, err := client.Write([]byte("hello again\n")); err != nil {
				t.Errorf("Client.Write failed: %s", err)
				return
			}
		}

		if test.validate != nil {
			if err := test.validate(client.ConnectionState()); err != nil {
				t.Errorf("validate callback returned error: %s", err)
			}
		}

		// If the server sent us an alert after our last flight, give it a
		// chance to arrive.
		if write && test.renegotiationExpectedToFail == 0 {
			client.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, err := client.Read(make([]byte, 1)); err != nil {
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					t.Errorf("final Read returned an error: %s", err)
				}
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
				serverConn.SetWriteDeadline(time.Now().Add(1 * time.Minute))
				serverConn.Write(b)
				continue
			}
			bb := make([]byte, len(b))
			serverConn.SetReadDeadline(time.Now().Add(1 * time.Minute))
			_, err := io.ReadFull(serverConn, bb)
			if err != nil {
				t.Fatalf("%s #%d: %s", test.name, i, err)
			}
			if !bytes.Equal(b, bb) {
				t.Fatalf("%s #%d: mismatch on read: got:%x want:%x", test.name, i, bb, b)
			}
		}
		// Give time to the send buffer to drain, to avoid the kernel
		// sending a RST and cutting off the flow. See Issue 18701.
		time.Sleep(10 * time.Millisecond)
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
			os.Stdout.Write(stdout.all)
			t.Fatalf("Client connection didn't work")
		}
		recordingConn.WriteTo(out)
		fmt.Printf("Wrote %s\n", path)
	}
}

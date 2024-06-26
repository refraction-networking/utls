// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

// helloStrategy is a sum type interface which allows us to pass either a ClientHelloID or a ClientHelloSpec and then act accordingly
type helloStrategy interface {
	helloName() string
}

type helloID struct {
	id ClientHelloID
}

func (hid *helloID) helloName() string {
	return hid.id.Str()
}

type helloSpec struct {
	name string
	spec *ClientHelloSpec
}

func (hs *helloSpec) helloName() string {
	return hs.name
}

func TestUTLSMarshalNoOp(t *testing.T) {
	str := "We rely on clientHelloMsg.marshal() not doing anything if clientHelloMsg.raw is set"
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "foobar"}, HelloGolang)
	msg, _, err := uconn.makeClientHello()
	if err != nil {
		t.Errorf("Got error: %s; expected to succeed", err)
	}
	msg.raw = []byte(str)
	marshalledHello, err := msg.marshal()
	if err != nil {
		t.Errorf("clientHelloMsg.marshal() returned error: %s", err.Error())
	}
	if strings.Compare(string(marshalledHello), str) != 0 {
		t.Errorf("clientHelloMsg.marshal() is not NOOP! Expected to get: %s, got: %s", str, string(marshalledHello))
	}
}

func TestUTLSHandshakeClientParrotGolang(t *testing.T) {
	hello := &helloID{HelloGolang}

	t.Skip("Skipping golang parroting tests until adjusting for new fingerprints")

	testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, hello)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, hello)

	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t, hello)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, hello)
}

func TestUTLSHandshakeClientParrotChrome_70(t *testing.T) {
	hello := &helloID{HelloChrome_70}

	testUTLSHandshakeClientTLS13_AES_128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientTLS13_AES_256_GCM_SHA384(t, hello)
	testUTLSHandshakeClientTLS13_CHACHA20_POLY1305_SHA256(t, hello)
	//testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, hello)
	//testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t, hello)

	//testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, hello)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, hello)

	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, hello)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, hello)
}

func TestUTLSHandshakeClientParrotChrome_58(t *testing.T) {
	hello := &helloID{HelloChrome_58}
	// TODO: EC tests below are disabled because latest version of reference OpenSSL doesn't support p256 nor p384
	// nor X25519 and I can't find configuration flag to enable it. Therefore I can't record replays.

	//testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, hello)
	//testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t, hello)

	//testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, hello)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, hello)

	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, hello)

	testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t, hello)
}

func TestUTLSHandshakeClientParrotFirefox_63(t *testing.T) {
	hello := &helloID{HelloFirefox_63}

	testUTLSHandshakeClientTLS13_AES_128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientTLS13_AES_256_GCM_SHA384(t, hello)
	testUTLSHandshakeClientTLS13_CHACHA20_POLY1305_SHA256(t, hello)

	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, hello)

	testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, hello)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, hello)

	//testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t, hello) TODO: enable when OpenSSL supports it
	testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t, hello)

	testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t, hello)

	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, hello)
}

func TestUTLSHandshakeClientParrotFirefox_55(t *testing.T) {
	hello := &helloID{HelloFirefox_55}

	testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t, hello)

	testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t, hello)
	testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t, hello)

	//testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t, hello) TODO: enable when OpenSSL supports it
	testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t, hello)

	testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t, hello)

	testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t, hello)
	testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t, hello)
}

func TestUTLSHandshakeClientParrotChrome_58_setclienthello(t *testing.T) {
	hello := &helloID{HelloChrome_58}
	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-setclienthello-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

// tests consistency of fingerprint after HelloRetryRequest
// chrome 70 is used, due to only specifying X25519 in keyshare, but being able to generate P-256 curve too
// openssl server, configured to use P-256, will send HelloRetryRequest
func TestUTLSHelloRetryRequest(t *testing.T) {
	hello := &helloID{HelloChrome_70}
	config := testConfig.Clone()
	config.CurvePreferences = []CurveID{X25519, CurveP256}

	test := &clientTest{
		name:   "UTLS-HelloRetryRequest-" + hello.helloName(),
		args:   []string{"-cipher", "ECDHE-RSA-AES128-GCM-SHA256", "-curves", "P-256"},
		config: config,
	}

	runUTLSClientTestTLS13(t, test, hello)
}

func TestUTLSRemoveSNIExtension(t *testing.T) {
	hello := &helloID{HelloChrome_70}

	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName() + "-OmitSNI",
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestForVersion(t, test, "TLSv12-", "-tls1_2", hello, true)
}

func TestUTLSServerNameIP(t *testing.T) {
	hello := &helloID{HelloChrome_70}

	config := getUTLSTestConfig()
	config.ServerName = "1.1.1.1"

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName() + "-ServerNameIP",
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestForVersion(t, test, "TLSv12-", "-tls1_2", hello, true)
}

func TestUTLSEmptyServerName(t *testing.T) {
	hello := &helloID{HelloChrome_70}

	config := getUTLSTestConfig()
	config.ServerName = ""

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName() + "-EmptyServerName",
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestForVersion(t, test, "TLSv12-", "-tls1_2", hello, true)
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
		MaxVersion:         VersionTLS13,
		CipherSuites:       allCipherSuites(),
		ServerName:         "foobar.com",
	}
	return testUTLSConfig
}

func testUTLSHandshakeClientECDHE_RSA_AES128_CBC_SHA(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-RSA-AES128-SHA"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_RSA_AES256_CBC_SHA(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-RSA-AES256-SHA"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES128_CBC_SHA(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-ECDSA-AES128-SHA"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES256_CBC_SHA(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-ECDSA-AES256-SHA"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientRSA_AES128_GCM_SHA256(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	opensslCipherName := "AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES128_GCM_SHA256(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-ECDSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_RSA_AES128_GCM_SHA256(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_ECDSA_AES256_GCM_SHA256(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-ECDSA-AES256-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_RSA_AES256_GCM_SHA256(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientTLS13_AES_128_GCM_SHA256(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()

	opensslCipherName := "TLS_AES_128_GCM_SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-ciphersuites", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS13(t, test, hello)
}

func testUTLSHandshakeClientTLS13_AES_256_GCM_SHA384(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()

	opensslCipherName := "TLS_AES_256_GCM_SHA384"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-ciphersuites", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS13(t, test, hello)
}

func testUTLSHandshakeClientTLS13_CHACHA20_POLY1305_SHA256(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()

	opensslCipherName := "TLS_CHACHA20_POLY1305_SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-ciphersuites", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS13(t, test, hello)
}

func testUTLSHandshakeClientECDHE_RSA_WITH_CHACHA20_POLY1305(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	config.CipherSuites = []uint16{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305}
	opensslCipherName := "ECDHE-RSA-CHACHA20-POLY1305"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func testUTLSHandshakeClientECDHE_ECDSA_WITH_CHACHA20_POLY1305(t *testing.T, hello helloStrategy) {
	config := getUTLSTestConfig()
	config.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305}
	opensslCipherName := "ECDHE-ECDSA-CHACHA20-POLY1305"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: config,
		cert:   testECDSACertificate,
		key:    testECDSAPrivateKey,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func runUTLSClientTestForVersion(t *testing.T, template *clientTest, prefix, option string, hello helloStrategy, omitSNI bool) {
	test := *template
	test.name = prefix + test.name
	if len(test.args) == 0 {
		test.args = defaultClientCommand
	}
	test.args = append([]string(nil), test.args...)
	test.args = append(test.args, option)
	test.runUTLS(t, *update, hello, omitSNI)
}

func runUTLSClientTestTLS12(t *testing.T, template *clientTest, hello helloStrategy) {
	runUTLSClientTestForVersion(t, template, "TLSv12-", "-tls1_2", hello, false)
}

func runUTLSClientTestTLS13(t *testing.T, template *clientTest, hello helloStrategy) {
	runUTLSClientTestForVersion(t, template, "TLSv13-", "-tls1_3", hello, false)
}

func (test *clientTest) runUTLS(t *testing.T, write bool, hello helloStrategy, omitSNIExtension bool) {
	checkOpenSSLVersion()

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

	var client *UConn
	switch h := hello.(type) {
	case *helloID:
		client = UClient(clientConn, config, h.id)
	case *helloSpec:
		client = UClient(clientConn, config, HelloCustom)
		if err := client.ApplyPreset(h.spec); err != nil {
			t.Errorf("got error: %v; expected to succeed", err)
			return
		}
	default:
		panic("unknown helloStrategy")
	}

	if omitSNIExtension {
		if err := client.RemoveSNIExtension(); err != nil {
			t.Error("Failed to remove SNI extension")
			return
		}
	}

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
			if err := recover(); err != nil {
				fmt.Printf("panic occurred: %v\n %s\n", err, string(debug.Stack()))
			}
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
				serverConn.SetWriteDeadline(time.Now().Add(2 * time.Second)) // [uTLS] 1min -> 2sec
				serverConn.Write(b)
				continue
			}
			bb := make([]byte, len(b))
			serverConn.SetReadDeadline(time.Now().Add(2 * time.Second)) // [uTLS] 1min -> 2sec
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

func TestUTLSMakeConnWithCompleteHandshake(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	masterSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47}
	clientRandom := []byte{40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71}
	serverRandom := []byte{80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111}
	serverTls := MakeConnWithCompleteHandshake(serverConn, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		masterSecret, clientRandom, serverRandom, false)
	clientTls := MakeConnWithCompleteHandshake(clientConn, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		masterSecret, clientRandom, serverRandom, true)

	clientMsg := []byte("Hello, world!")
	serverMsg := []byte("Test response!")

	go func() {
		clientTls.Write(clientMsg)
		resp := make([]byte, 20)
		read, err := clientTls.Read(resp)
		if !bytes.Equal(resp[:read], serverMsg) {
			t.Errorf("client expected to receive: %v, got %v\n",
				serverMsg, resp[:read])
		}
		if err != nil {
			t.Errorf("error reading client: %+v\n", err)
		}
		clientConn.Close()
	}()

	buf := make([]byte, 20)
	read, err := serverTls.Read(buf)
	if !bytes.Equal(buf[:read], clientMsg) {
		t.Errorf("server expected to receive: %v, got %v\n",
			clientMsg, buf[:read])
	}
	if err != nil {
		t.Errorf("error reading client: %+v\n", err)
	}

	serverTls.Write(serverMsg)
}

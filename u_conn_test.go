// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
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
	marshalledHello := msg.marshal()
	if strings.Compare(string(marshalledHello), str) != 0 {
		t.Errorf("clientHelloMsg.marshal() is not NOOP! Expected to get: %s, got: %s", str, string(marshalledHello))
	}
}

func TestUTLSHandshakeClientParrotGolang(t *testing.T) {
	hello := &helloID{HelloGolang}

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

func TestUTLSHandshakeClientFingerprintedSpecFromChrome_58(t *testing.T) {
	helloID := HelloChrome_58
	serverName := "foobar"
	originalConfig := getUTLSTestConfig()
	originalConfig.ServerName = serverName
	uconn := UClient(&net.TCPConn{}, originalConfig, helloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	f := &Fingerprinter{}
	generatedSpec, err := f.FingerprintClientHello(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	hello := &helloSpec{
		name: fmt.Sprintf("%v-fingerprinted", helloID.Str()),
		spec: generatedSpec,
	}

	newConfig := getUTLSTestConfig()
	newConfig.ServerName = serverName

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-cipher", opensslCipherName},
		config: newConfig,
	}

	runUTLSClientTestTLS12(t, test, hello)
}

func TestUTLSHandshakeClientFingerprintedSpecFromChrome_70(t *testing.T) {
	helloID := HelloChrome_70
	serverName := "foobar"
	originalConfig := getUTLSTestConfig()
	originalConfig.ServerName = serverName

	uconn := UClient(&net.TCPConn{}, originalConfig, helloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	f := &Fingerprinter{}
	generatedSpec, err := f.FingerprintClientHello(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	hello := &helloSpec{
		name: fmt.Sprintf("%v-fingerprinted", helloID.Str()),
		spec: generatedSpec,
	}

	newConfig := getUTLSTestConfig()
	newConfig.ServerName = serverName

	opensslCipherName := "TLS_AES_128_GCM_SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
		args:   []string{"-ciphersuites", opensslCipherName},
		config: newConfig,
	}

	runUTLSClientTestTLS13(t, test, hello)
}

func TestUTLSHandshakeClientFingerprintedSpecFromRaw(t *testing.T) {
	// Handshake Protocol: Client Hello
	//     Handshake Type: Client Hello (1)
	//     Length: 508
	//     Version: TLS 1.2 (0x0303)
	//     Random: 7fd76fa530c24816ea9e4a6cf2e939f2350b9486a7bac58e…
	//     Session ID Length: 32
	//     Session ID: d9b01fc4f4b6fe14fe9ce652442d66588d982cb25913d866…
	//     Cipher Suites Length: 36
	//     Cipher Suites (18 suites)
	//         Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
	//         Cipher Suite: TLS_CHACHA20_POLY1305_SHA256 (0x1303)
	//         Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
	//         Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
	//         Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
	//         Cipher Suite: TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca9)
	//         Cipher Suite: TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (0xcca8)
	//         Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
	//         Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
	//         Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
	//         Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
	//         Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
	//         Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
	//         Cipher Suite: TLS_RSA_WITH_AES_128_GCM_SHA256 (0x009c)
	//         Cipher Suite: TLS_RSA_WITH_AES_256_GCM_SHA384 (0x009d)
	//         Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
	//         Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
	//         Cipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
	//     Compression Methods Length: 1
	//     Compression Methods (1 method)
	//     Extensions Length: 399
	//     Extension: server_name (len=34)
	//         Type: server_name (0)
	//         Length: 34
	//         Server Name Indication extension
	//     Extension: extended_master_secret (len=0)
	//         Type: extended_master_secret (23)
	//         Length: 0
	//     Extension: renegotiation_info (len=1)
	//         Type: renegotiation_info (65281)
	//         Length: 1
	//         Renegotiation Info extension
	//     Extension: supported_groups (len=14)
	//         Type: supported_groups (10)
	//         Length: 14
	//         Supported Groups List Length: 12
	//         Supported Groups (6 groups)
	//     Extension: ec_point_formats (len=2)
	//         Type: ec_point_formats (11)
	//         Length: 2
	//         EC point formats Length: 1
	//         Elliptic curves point formats (1)
	//     Extension: application_layer_protocol_negotiation (len=14)
	//         Type: application_layer_protocol_negotiation (16)
	//         Length: 14
	//         ALPN Extension Length: 12
	//         ALPN Protocol
	//     Extension: status_request (len=5)
	//         Type: status_request (5)
	//         Length: 5
	//         Certificate Status Type: OCSP (1)
	//         Responder ID list Length: 0
	//         Request Extensions Length: 0
	//     Extension: key_share (len=107)
	//         Type: key_share (51)
	//         Length: 107
	//         Key Share extension
	//     Extension: supported_versions (len=5)
	//         Type: supported_versions (43)
	//         Length: 5
	//         Supported Versions length: 4
	//         Supported Version: TLS 1.3 (0x0304)
	//         Supported Version: TLS 1.2 (0x0303)
	//     Extension: signature_algorithms (len=24)
	//         Type: signature_algorithms (13)
	//         Length: 24
	//         Signature Hash Algorithms Length: 22
	//         Signature Hash Algorithms (11 algorithms)
	//     Extension: record_size_limit (len=2)
	//         Type: record_size_limit (28)
	//         Length: 2
	//         Record Size Limit: 16385
	//     Extension: padding (len=143)
	//         Type: padding (21)
	//         Length: 143
	//         Padding Data: 000000000000000000000000000000000000000000000000…
	byteString := []byte("010001fc03037fd76fa530c24816ea9e4a6cf2e939f2350b9486a7bac58ece5753767fb6112420d9b01fc4f4b6fe14fe9ce652442d66588d982cb25913d866348bde54d3899abe0024130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a0100018f00000022002000001d70656f706c652d70612e636c69656e7473362e676f6f676c652e636f6d00170000ff01000100000a000e000c001d00170018001901000101000b000201000010000e000c02683208687474702f312e310005000501000000000033006b0069001d002065e566ff33dfbeb012e3b13b87d75612bd0fbc3963673df90afed533dccc9b5400170041047fcc2666d04c31272a2e39905c771a89edf5a71dae301ec2fa0e7bc4d0e06580a0d36324e3dc4f29e200a8905badd11c00daf11588977bf501597dac5fdc55bf002b00050403040303000d0018001604030503060308040805080604010501060102030201001c000240010015008f0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
	helloBytes := make([]byte, hex.DecodedLen(len(byteString)))
	_, err := hex.Decode(helloBytes, byteString)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
		return
	}

	f := &Fingerprinter{}
	generatedSpec, err := f.FingerprintClientHello(helloBytes)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	hello := &helloSpec{
		name: "raw-capture-fingerprinted",
		spec: generatedSpec,
	}

	config := getUTLSTestConfig()

	opensslCipherName := "ECDHE-RSA-AES128-GCM-SHA256"
	test := &clientTest{
		name:   "UTLS-" + opensslCipherName + "-" + hello.helloName(),
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
	test.runUTLS(t, *update, hello, false)
}

func runUTLSClientTestTLS12(t *testing.T, template *clientTest, hello helloStrategy) {
	runUTLSClientTestForVersion(t, template, "TLSv12-", "-tls1_2", hello, false)
}

func runUTLSClientTestTLS13(t *testing.T, template *clientTest, hello helloStrategy) {
	runUTLSClientTestForVersion(t, template, "TLSv13-", "-tls1_3", hello, false)
}

func (test *clientTest) runUTLS(t *testing.T, write bool, hello helloStrategy, omitSNIExtension bool) {
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

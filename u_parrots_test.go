// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"io/ioutil"
	"net"
	"reflect"
	"testing"
)

func assertEquality(t *testing.T, fieldName string, expected, actual interface{}) {
	if kActual, ok := actual.(KeyShare); ok {
		kExpected := expected.(KeyShare)
		assertEquality(t, fieldName, kExpected.Group, kActual.Group)
		return
	}

	if fieldName == "SupportedCurves" || fieldName == "KeyShares" {
		cExpected := expected.(CurveID)
		cActual := actual.(CurveID)
		if isGREASEUint16(uint16(cExpected)) && isGREASEUint16(uint16(cActual)) {
			return
		}
	}

	if fieldName == "SupportedVersions" || fieldName == "CipherSuites" {
		cExpected := expected.(uint16)
		cActual := actual.(uint16)
		if isGREASEUint16(cExpected) && isGREASEUint16(cActual) {
			return
		}
	}

	if expected != actual {
		t.Errorf("%v fields not equal, expected: %v, got: %v", fieldName, expected, actual)
	}
}

func compareClientHelloFields(t *testing.T, fieldName string, expected, actual *ClientHelloMsg) {
	rExpected := reflect.ValueOf(expected)
	if rExpected.Kind() != reflect.Ptr || rExpected.Elem().Kind() != reflect.Struct {
		t.Errorf("Error using reflect to compare Hello fields")
	}
	rActual := reflect.ValueOf(actual)
	if rActual.Kind() != reflect.Ptr || rActual.Elem().Kind() != reflect.Struct {
		t.Errorf("Error using reflect to compare Hello fields")
	}

	rExpected = rExpected.Elem()
	rActual = rActual.Elem()

	fExpected := rExpected.FieldByName(fieldName)
	fActual := rActual.FieldByName(fieldName)
	if !(fExpected.IsValid() && fActual.IsValid()) {
		t.Errorf("Error using reflect to lookup Hello field name: %v", fieldName)
	}

	if fExpected.Kind() == reflect.Slice {
		sExpected := fExpected.Slice(0, fExpected.Len())
		sActual := fActual.Slice(0, fActual.Len())

		if sExpected.Len() != sActual.Len() {
			t.Errorf("%v fields slice length not equal, expected: %v, got: %v", fieldName, fExpected, fActual)
		}

		for i := 0; i < sExpected.Len(); i++ {
			assertEquality(t, fieldName, sExpected.Index(i).Interface(), sActual.Index(i).Interface())
		}
	} else {
		assertEquality(t, fieldName, fExpected.Interface(), fActual.Interface())
	}
}

func checkUTLSExtensionsEquality(t *testing.T, expected, actual TLSExtension) {
	if _, ok := expected.(*UtlsGREASEExtension); ok {
		if _, ok := actual.(*UtlsGREASEExtension); ok {
			// Good enough that they're both GREASE
			return
		}
	}

	if expected.Len() != actual.Len() {
		t.Errorf("extension types length not equal\nexpected: %#v\ngot: %#v", expected, actual)
	}

	actualBytes, err := ioutil.ReadAll(actual)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	expectedBytes, err := ioutil.ReadAll(expected)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	logInequality := func() {
		t.Errorf("extensions not equal\nexpected: %#v\nbytes:%#x\ngot: %#v\nbytes: %#x", expected, expectedBytes, actual, actualBytes)
	}

	if !bytes.Equal(expectedBytes, actualBytes) {
		// handle all the cases where GREASE or other factors can cause byte unalignment

		// at this point concrete types must match
		expectedType := reflect.TypeOf(expected)
		actualType := reflect.TypeOf(actual)
		if expectedType != actualType {
			t.Errorf("extensions not equal\nexpected: %#v\nbytes:%#x\ngot: %#v\nbytes: %#x", expected, expectedBytes, actual, actualBytes)
			return
		}

		switch expectedExtension := expected.(type) {
		case *SupportedCurvesExtension:
			actualExtension := expected.(*SupportedCurvesExtension)
			for i, expectedCurve := range expectedExtension.Curves {
				actualCurve := actualExtension.Curves[i]
				if expectedCurve == actualCurve {
					continue
				}
				if isGREASEUint16(uint16(expectedCurve)) && isGREASEUint16(uint16(actualCurve)) {
					continue
				}
				logInequality()
				return
			}
		case *KeyShareExtension:
			actualExtension := expected.(*KeyShareExtension)
			for i, expectedKeyShare := range expectedExtension.KeyShares {
				actualKeyShare := actualExtension.KeyShares[i]
				if bytes.Equal(actualKeyShare.Data, expectedKeyShare.Data) {
					continue
				}
				if isGREASEUint16(uint16(expectedKeyShare.Group)) && isGREASEUint16(uint16(actualKeyShare.Group)) {
					continue
				}
				logInequality()
				return
			}
		case *SupportedVersionsExtension:
			actualExtension := expected.(*SupportedVersionsExtension)
			for i, expectedVersion := range expectedExtension.Versions {
				actualVersion := actualExtension.Versions[i]
				if isGREASEUint16(expectedVersion) && isGREASEUint16(actualVersion) || actualVersion == expectedVersion {
					continue
				}
				logInequality()
				return
			}
		default:
			logInequality()
			return
		}
	}

}

func checkUTLSFingerPrintClientHello(t *testing.T, clientHelloID ClientHelloID, serverName string) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, clientHelloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	generatedUConn := UClient(&net.TCPConn{}, &Config{ServerName: "foobar"}, HelloCustom)
	generatedSpec, err := FingerprintClientHello(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := generatedUConn.ApplyPreset(generatedSpec); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := generatedUConn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	if len(uconn.HandshakeState.Hello.Raw) != len(generatedUConn.HandshakeState.Hello.Raw) {
		t.Errorf("UConn from fingerprint has %d length, should have %d", len(generatedUConn.HandshakeState.Hello.Raw), len(uconn.HandshakeState.Hello.Raw))
	}

	// We can't effectively check the extensions on randomized client hello ids
	if !(clientHelloID == HelloRandomized || clientHelloID == HelloRandomizedALPN || clientHelloID == HelloRandomizedNoALPN) {
		for i, originalExtension := range uconn.Extensions {
			if _, ok := originalExtension.(*UtlsPaddingExtension); ok {
				// We can't really compare padding extensions in this way
				continue
			}

			generatedExtension := generatedUConn.Extensions[i]
			checkUTLSExtensionsEquality(t, originalExtension, generatedExtension)
		}
	}

	fieldsToTest := []string{
		"Vers", "CipherSuites", "CompressionMethods", "NextProtoNeg", "ServerName", "OcspStapling", "Scts", "SupportedCurves",
		"SupportedPoints", "TicketSupported", "SupportedSignatureAlgorithms", "SecureRenegotiation", "SecureRenegotiationSupported", "AlpnProtocols",
		"SupportedSignatureAlgorithmsCert", "SupportedVersions", "KeyShares", "EarlyData", "PskModes", "PskIdentities", "PskBinders",
	}

	for _, field := range fieldsToTest {
		compareClientHelloFields(t, field, uconn.HandshakeState.Hello, generatedUConn.HandshakeState.Hello)
	}
}

func TestUTLSFingerprintClientHello(t *testing.T) {
	clientHellosToTest := []ClientHelloID{
		HelloChrome_58, HelloChrome_70, HelloChrome_83, HelloFirefox_55, HelloFirefox_63, HelloIOS_11_1, HelloIOS_12_1, HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN}

	serverNames := []string{"foobar"}

	for _, clientHello := range clientHellosToTest {
		for _, serverName := range serverNames {
			t.Logf("checking fingerprint generated client hello spec against %v and server name: %v", clientHello, serverName)
			checkUTLSFingerPrintClientHello(t, clientHello, "foobar")
		}
	}
}

func TestUTLSIsGrease(t *testing.T) {
	var testMap = []struct {
		version  uint16
		isGREASE bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a1a, false},
		{0x2a2a, true},
		{0x1234, false},
		{0x1a2a, false},
		{0xdeed, false},
		{0xb1b1, false},
	}

	for _, testCase := range testMap {
		if isGREASEUint16(testCase.version) != testCase.isGREASE {
			t.Errorf("misidentified GREASE: testing %x, isGREASE: %v", testCase.version, isGREASEUint16(testCase.version))
		}
	}
}

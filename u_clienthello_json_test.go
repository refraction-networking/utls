package tls

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestClientHelloSpecJSONUnmarshaler(t *testing.T) {
	testClientHelloSpecJSONUnmarshaler_Chrome102(t)
}

func testClientHelloSpecJSONUnmarshaler_Chrome102(t *testing.T) {
	jsonCH, err := os.ReadFile("testdata/ClientHello-JSON-Chrome102.json")
	if err != nil {
		t.Fatal(err)
	}

	var chsju ClientHelloSpecJSONUnmarshaler
	if err := json.Unmarshal(jsonCH, &chsju); err != nil {
		t.Fatal(err)
	}

	savedChrome102, _ := utlsIdToSpec(HelloChrome_102)
	jsonCHS := chsju.ClientHelloSpec()

	// Compare CipherSuites
	if !reflect.DeepEqual(jsonCHS.CipherSuites, savedChrome102.CipherSuites) {
		t.Errorf("got %#v, want %#v", jsonCHS.CipherSuites, savedChrome102.CipherSuites)
	}

	// Compare CompressionMethods
	if !reflect.DeepEqual(jsonCHS.CompressionMethods, savedChrome102.CompressionMethods) {
		t.Errorf("got %#v, want %#v", jsonCHS.CompressionMethods, savedChrome102.CompressionMethods)
	}

	// Compare Extensions
	if len(jsonCHS.Extensions) != len(savedChrome102.Extensions) {
		t.Errorf("len(jsonCHS.Extensions) = %d != %d = len(savedChrome102.Extensions)", len(jsonCHS.Extensions), len(savedChrome102.Extensions))
	}

	for i := range jsonCHS.Extensions {
		if !reflect.DeepEqual(jsonCHS.Extensions[i], savedChrome102.Extensions[i]) {
			if _, ok := jsonCHS.Extensions[i].(*UtlsPaddingExtension); ok {
				continue // UtlsPaddingExtension has non-nil function member
			}
			t.Errorf("got %#v, want %#v", jsonCHS.Extensions[i], savedChrome102.Extensions[i])
		}
	}
}

func TestClientHelloSpecUnmarshalJSON(t *testing.T) {
	testClientHelloSpecUnmarshalJSON_Chrome102(t)
}

func testClientHelloSpecUnmarshalJSON_Chrome102(t *testing.T) {
	var chs ClientHelloSpec
	jsonCH, err := os.ReadFile("testdata/ClientHello-JSON-Chrome102.json")
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(jsonCH, &chs); err != nil {
		t.Fatal(err)
	}

	savedChrome102, _ := utlsIdToSpec(HelloChrome_102)

	// Compare CipherSuites
	if !reflect.DeepEqual(chs.CipherSuites, savedChrome102.CipherSuites) {
		t.Errorf("got %#v, want %#v", chs.CipherSuites, savedChrome102.CipherSuites)
	}

	// Compare CompressionMethods
	if !reflect.DeepEqual(chs.CompressionMethods, savedChrome102.CompressionMethods) {
		t.Errorf("got %#v, want %#v", chs.CompressionMethods, savedChrome102.CompressionMethods)
	}

	// Compare Extensions
	if len(chs.Extensions) != len(savedChrome102.Extensions) {
		t.Errorf("len(chs.Extensions) = %d != %d = len(savedChrome102.Extensions)", len(chs.Extensions), len(savedChrome102.Extensions))
	}

	for i := range chs.Extensions {
		if !reflect.DeepEqual(chs.Extensions[i], savedChrome102.Extensions[i]) {
			if _, ok := chs.Extensions[i].(*UtlsPaddingExtension); ok {
				continue // UtlsPaddingExtension has non-nil function member
			}
			t.Errorf("got %#v, want %#v", chs.Extensions[i], savedChrome102.Extensions[i])
		}
	}
}

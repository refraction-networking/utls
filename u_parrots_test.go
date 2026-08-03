package tls

import (
	"bytes"
	"net"
	"reflect"
	"slices"
	"testing"
)

type incrementingSource struct {
	next byte
}

func (s *incrementingSource) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = s.next
		s.next++
	}
	return len(b), nil
}

func findKeyShareExtension(t *testing.T, exts []TLSExtension) *KeyShareExtension {
	t.Helper()

	for _, ext := range exts {
		if keyShareExt, ok := ext.(*KeyShareExtension); ok {
			return keyShareExt
		}
	}

	t.Fatal("key_share extension not found")
	return nil
}

func findKeyShareData(t *testing.T, keyShareExt *KeyShareExtension, group CurveID) []byte {
	t.Helper()

	for _, keyShare := range keyShareExt.KeyShares {
		if keyShare.Group == group {
			return keyShare.Data
		}
	}

	t.Fatalf("key_share for group %v not found", group)
	return nil
}

func newTestUConnWithIncrementingRand() *UConn {
	return UClient(&net.TCPConn{}, &Config{
		ServerName: "example.com",
		Rand:       &incrementingSource{},
	}, HelloCustom)
}

func fingerprintsWithHybridClassicalKeyShareReuse() []ClientHelloID {
	return []ClientHelloID{
		HelloFirefox_148,
	}
}

func TestParrotFingerprintsReuseHybridClassicalKeyShare(t *testing.T) {
	for _, helloID := range fingerprintsWithHybridClassicalKeyShareReuse() {
		t.Run(helloID.Str(), func(t *testing.T) {
			spec, err := UTLSIdToSpec(helloID)
			if err != nil {
				t.Fatalf("unexpected error creating %s spec: %v", helloID.Str(), err)
			}

			uconn := newTestUConnWithIncrementingRand()
			if err := uconn.ApplyPreset(&spec); err != nil {
				t.Fatalf("unexpected error applying %s spec: %v", helloID.Str(), err)
			}

			keyShareExt := findKeyShareExtension(t, uconn.Extensions)
			hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
			classicalData := findKeyShareData(t, keyShareExt, X25519)

			if len(hybridData) < x25519PublicKeySize {
				t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
			}
			hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
			if !bytes.Equal(hybridClassicalPart, classicalData) {
				t.Fatalf("expected %s to reuse classical keyshare: hybrid classical part != X25519 keyshare", helloID.Str())
			}

			keys := uconn.HandshakeState.State13.KeyShareKeys
			if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
				t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
			}
			if keys.MlkemEcdhe != keys.Ecdhe {
				t.Fatalf("expected %s hybrid/classical keyshares to reuse the same ECDHE private key", helloID.Str())
			}
		})
	}
}

func TestHybridClassicalKeySharesAreIndependentByDefault(t *testing.T) {
	spec := ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
		},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SupportedCurvesExtension{
				Curves: []CurveID{
					X25519MLKEM768,
					X25519,
				},
			},
			&KeyShareExtension{
				KeyShares: []KeyShare{
					{
						Group: X25519MLKEM768,
					},
					{
						Group: X25519,
					},
				},
			},
			&SupportedVersionsExtension{
				Versions: []uint16{
					VersionTLS13,
					VersionTLS12,
				},
			},
		},
	}

	uconn := newTestUConnWithIncrementingRand()
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying independent keyshare spec: %v", err)
	}

	keyShareExt := findKeyShareExtension(t, uconn.Extensions)
	hybridData := findKeyShareData(t, keyShareExt, X25519MLKEM768)
	classicalData := findKeyShareData(t, keyShareExt, X25519)

	if len(hybridData) < x25519PublicKeySize {
		t.Fatalf("hybrid keyshare is too short: got %d bytes", len(hybridData))
	}
	hybridClassicalPart := hybridData[len(hybridData)-x25519PublicKeySize:]
	if bytes.Equal(hybridClassicalPart, classicalData) {
		t.Fatalf("expected independent keyshares by default: hybrid classical part == X25519 keyshare")
	}

	keys := uconn.HandshakeState.State13.KeyShareKeys
	if keys == nil || keys.MlkemEcdhe == nil || keys.Ecdhe == nil {
		t.Fatal("expected both hybrid and classical ECDHE private keys to be set")
	}
	if keys.MlkemEcdhe == keys.Ecdhe {
		t.Fatal("expected independent keyshares by default: hybrid/classical ECDHE private keys should differ")
	}
}

func findSignatureAlgorithmsExtension(t *testing.T, exts []TLSExtension) []SignatureScheme {
	t.Helper()

	for _, ext := range exts {
		if sigExt, ok := ext.(*SignatureAlgorithmsExtension); ok {
			return sigExt.SupportedSignatureAlgorithms
		}
	}

	t.Fatal("signature_algorithms extension not found")
	return nil
}

func hasApplicationSettingsNewExtension(exts []TLSExtension) bool {
	for _, ext := range exts {
		if _, ok := ext.(*ApplicationSettingsExtensionNew); ok {
			return true
		}
	}
	return false
}

func hasPreSharedKeyExtension(exts []TLSExtension) bool {
	for _, ext := range exts {
		if _, ok := ext.(*UtlsPreSharedKeyExtension); ok {
			return true
		}
	}
	return false
}

func hasTrustAnchorsExtension(exts []TLSExtension) bool {
	for _, ext := range exts {
		if genericExt, ok := ext.(*GenericExtension); ok && genericExt.Id == 0xca34 {
			return true
		}
		if reflect.TypeOf(ext).String() == "*tls.TrustAnchorsExtension" {
			return true
		}
	}
	return false
}

func expectedChrome150SignatureAlgorithms() []SignatureScheme {
	return []SignatureScheme{
		MLDSA44,
		MLDSA65,
		MLDSA87,
		ECDSAWithP256AndSHA256,
		PSSWithSHA256,
		PKCS1WithSHA256,
		ECDSAWithP384AndSHA384,
		PSSWithSHA384,
		PKCS1WithSHA384,
		PSSWithSHA512,
		PKCS1WithSHA512,
	}
}

func TestHelloChrome150PrependsMLDSASignatureAlgorithms(t *testing.T) {
	spec, err := UTLSIdToSpec(HelloChrome_150)
	if err != nil {
		t.Fatalf("unexpected error creating Chrome 150 spec: %v", err)
	}

	sigAlgs := findSignatureAlgorithmsExtension(t, spec.Extensions)
	expected := expectedChrome150SignatureAlgorithms()
	if !slices.Equal(sigAlgs, expected) {
		t.Fatalf("unexpected Chrome 150 signature algorithms:\nwant %v\ngot  %v", expected, sigAlgs)
	}
	if !hasApplicationSettingsNewExtension(spec.Extensions) {
		t.Fatal("expected Chrome 150 to keep the new ALPS extension codepoint")
	}
	if hasTrustAnchorsExtension(spec.Extensions) {
		t.Fatal("expected Chrome 150 not to advertise the trust anchors extension")
	}
}

func TestHelloChromeAutoTracksGoMLDSASupport(t *testing.T) {
	expected := HelloChrome_133
	if goMLDSASupported() {
		expected = HelloChrome_150
	}
	if HelloChrome_Auto != expected {
		t.Fatalf("unexpected HelloChrome_Auto: want %s, got %s", expected.Str(), HelloChrome_Auto.Str())
	}
}

func TestHelloChrome150PSKPrependsMLDSASignatureAlgorithms(t *testing.T) {
	spec, err := UTLSIdToSpec(HelloChrome_150_PSK)
	if err != nil {
		t.Fatalf("unexpected error creating Chrome 150 PSK spec: %v", err)
	}

	sigAlgs := findSignatureAlgorithmsExtension(t, spec.Extensions)
	expected := expectedChrome150SignatureAlgorithms()
	if !slices.Equal(sigAlgs, expected) {
		t.Fatalf("unexpected Chrome 150 PSK signature algorithms:\nwant %v\ngot  %v", expected, sigAlgs)
	}
	if !hasApplicationSettingsNewExtension(spec.Extensions) {
		t.Fatal("expected Chrome 150 PSK to keep the new ALPS extension codepoint")
	}
	if hasTrustAnchorsExtension(spec.Extensions) {
		t.Fatal("expected Chrome 150 PSK not to advertise the trust anchors extension")
	}
	if !hasPreSharedKeyExtension(spec.Extensions) {
		t.Fatal("expected Chrome 150 PSK to keep the pre-shared key extension")
	}
}

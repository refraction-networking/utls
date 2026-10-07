package tls

import (
	"net"
	"testing"
)

// sigAlgGREASESpec makes a small spec. Its signature_algorithms extension starts with
// the GREASE placeholder, the same way the Chrome list starts with a GREASE value.
// Each connection needs a new spec, because ApplyPreset writes over the placeholder in
// the extension.
func sigAlgGREASESpec() ClientHelloSpec {
	return ClientHelloSpec{
		TLSVersMin:         VersionTLS12,
		TLSVersMax:         VersionTLS13,
		CipherSuites:       []uint16{TLS_AES_128_GCM_SHA256},
		CompressionMethods: []uint8{compressionNone},
		Extensions: []TLSExtension{
			&SignatureAlgorithmsExtension{
				SupportedSignatureAlgorithms: []SignatureScheme{
					SignatureScheme(GREASE_PLACEHOLDER),
					ECDSAWithP256AndSHA256,
					PSSWithSHA256,
					PKCS1WithSHA256,
				},
			},
		},
	}
}

// applySigAlgGREASESpec applies a new spec to a new connection. It returns the
// signature algorithms that ApplyPreset wrote.
func applySigAlgGREASESpec(t *testing.T) []SignatureScheme {
	t.Helper()

	spec := sigAlgGREASESpec()
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying signature algorithms spec: %v", err)
	}

	for _, ext := range uconn.Extensions {
		if sigAlgExt, ok := ext.(*SignatureAlgorithmsExtension); ok {
			return sigAlgExt.SupportedSignatureAlgorithms
		}
	}

	t.Fatal("signature_algorithms extension not found")
	return nil
}

// TestSignatureAlgorithmsGREASESubstitution checks three properties of the
// substitution:
//
//  1. ApplyPreset replaces the GREASE placeholder in signature_algorithms with a real
//     GREASE value.
//  2. ApplyPreset draws that value again for each connection.
//  3. ApplyPreset keeps the other signature algorithms unchanged.
//
// Without the substitution, the literal placeholder 0x0a0a goes on the wire on every
// connection. That constant is a reliable "this is not Chrome" signal.
func TestSignatureAlgorithmsGREASESubstitution(t *testing.T) {
	const connections = 64

	values := make(map[SignatureScheme]bool)
	for i := 0; i < connections; i++ {
		sigAlgs := applySigAlgGREASESpec(t)
		if len(sigAlgs) != 4 {
			t.Fatalf("signature_algorithms holds %d entries, want 4", len(sigAlgs))
		}

		if !isGREASEUint16(uint16(sigAlgs[0])) {
			t.Fatalf("substituted signature algorithm = %#04x, which is not a 0x?a?a value", uint16(sigAlgs[0]))
		}

		if sigAlgs[1] != ECDSAWithP256AndSHA256 || sigAlgs[2] != PSSWithSHA256 || sigAlgs[3] != PKCS1WithSHA256 {
			t.Fatalf("non-GREASE signature algorithms were rewritten: got %#04x, %#04x, %#04x",
				uint16(sigAlgs[1]), uint16(sigAlgs[2]), uint16(sigAlgs[3]))
		}

		values[sigAlgs[0]] = true
	}

	// There are 16 GREASE values. A run that returns the placeholder, or any other
	// constant, therefore gives one distinct value. This test asks for more than one
	// distinct value only. 64 draws from 16 values usually give a much larger count.
	// A larger minimum would fail on an unlucky run.
	if len(values) < 2 {
		t.Errorf("%d connections produced only %d distinct GREASE signature algorithms", connections, len(values))
	}
	if values[SignatureScheme(GREASE_PLACEHOLDER)] && len(values) == 1 {
		t.Error("the GREASE placeholder was sent unchanged")
	}
}

// TestSignatureAlgorithmsGREASEMatchesSeed checks that the substituted value comes
// from the per-connection GREASE seed, and not from a separate random draw. BoringSSL
// derives every GREASE value in one ClientHello from that one seed. This test also
// checks that the value comes from the seed index reserved for signature algorithms.
func TestSignatureAlgorithmsGREASEMatchesSeed(t *testing.T) {
	spec := sigAlgGREASESpec()
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: "example.com"}, HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		t.Fatalf("unexpected error applying signature algorithms spec: %v", err)
	}

	var got SignatureScheme
	for _, ext := range uconn.Extensions {
		if sigAlgExt, ok := ext.(*SignatureAlgorithmsExtension); ok {
			got = sigAlgExt.SupportedSignatureAlgorithms[0]
		}
	}

	want := SignatureScheme(GetBoringGREASEValue(uconn.greaseSeed, ssl_grease_signature_algorithm))
	if got != want {
		t.Errorf("substituted signature algorithm = %#04x, want the seeded value %#04x", uint16(got), uint16(want))
	}
}

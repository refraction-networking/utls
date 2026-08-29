package tls

import (
	"crypto/mldsa"
	"crypto/rand"
	"testing"
)

// TestMLDSASignatureSchemeValues checks the codepoints of the ML-DSA schemes. The
// values come from RFC 9881 and agree with Go 1.27 crypto/tls.
func TestMLDSASignatureSchemeValues(t *testing.T) {
	for _, tc := range []struct {
		scheme SignatureScheme
		want   uint16
	}{
		{MLDSA44, 0x0904},
		{MLDSA65, 0x0905},
		{MLDSA87, 0x0906},
	} {
		if uint16(tc.scheme) != tc.want {
			t.Errorf("%v holds the value 0x%04x, but the test expects 0x%04x",
				tc.scheme, uint16(tc.scheme), tc.want)
		}
	}
}

// TestTypeAndHashFromMLDSAScheme checks that the 3 ML-DSA schemes map to the ML-DSA
// signature type, and that they use no pre-hash.
func TestTypeAndHashFromMLDSAScheme(t *testing.T) {
	for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		sigType, hash, err := typeAndHashFromSignatureScheme(scheme)
		if err != nil {
			t.Errorf("typeAndHashFromSignatureScheme(%v) gives the error %v", scheme, err)

			continue
		}
		if sigType != signatureMLDSA {
			t.Errorf("%v maps to the signature type %d, but the test expects signatureMLDSA (%d)",
				scheme, sigType, signatureMLDSA)
		}
		if hash != directSigning {
			t.Errorf("%v maps to the hash %v, but the test expects directSigning", scheme, hash)
		}
	}
}

// TestVerifyMLDSAHandshakeSignature signs a message with an ML-DSA key, then verifies
// the signature through the handshake code. The test uses no certificate, because it
// covers the signature step only.
func TestVerifyMLDSAHandshakeSignature(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("cannot make an ML-DSA key: %v", err)
	}

	signed := []byte("the transcript that the CertificateVerify message signs")
	signature, err := key.Sign(rand.Reader, signed, &mldsa.Options{})
	if err != nil {
		t.Fatalf("cannot sign: %v", err)
	}

	if err := verifyHandshakeSignature(signatureMLDSA, key.PublicKey(), directSigning, signed, signature); err != nil {
		t.Errorf("the correct signature does not verify: %v", err)
	}

	signed[0] ^= 0xff
	if err := verifyHandshakeSignature(signatureMLDSA, key.PublicKey(), directSigning, signed, signature); err == nil {
		t.Error("a signature over different data verifies, but the test expects an error")
	}
}

// holdsScheme reports whether a list holds a scheme.
func holdsScheme(list []SignatureScheme, want SignatureScheme) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}

	return false
}

// TestClientSupportedSignatureAlgorithms checks that a client offers the ML-DSA schemes
// for TLS 1.3 only. The ML-DSA codepoints are defined for TLS 1.3 only.
func TestClientSupportedSignatureAlgorithms(t *testing.T) {
	tls13 := clientSupportedSignatureAlgorithms(VersionTLS13)
	for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		if !holdsScheme(tls13, scheme) {
			t.Errorf("the TLS 1.3 client list holds no %v", scheme)
		}
	}

	tls12 := clientSupportedSignatureAlgorithms(VersionTLS12)
	for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		if holdsScheme(tls12, scheme) {
			t.Errorf("the TLS 1.2 client list holds %v, but ML-DSA needs TLS 1.3", scheme)
		}
	}
}

// TestServerListHoldsNoMLDSA checks the shared list that the 3 server call sites read.
// A uTLS server must not advertise the ML-DSA codepoints, and must not accept an ML-DSA
// client certificate. This test fails if a later change puts ML-DSA in the shared list.
func TestServerListHoldsNoMLDSA(t *testing.T) {
	shared := supportedSignatureAlgorithms()
	for _, scheme := range []SignatureScheme{MLDSA44, MLDSA65, MLDSA87} {
		if holdsScheme(shared, scheme) {
			t.Errorf("supportedSignatureAlgorithms holds %v, thus a server advertises it", scheme)
		}
		// This is the guard at handshake_server_tls13.go:1092.
		if isSupportedSignatureAlgorithm(scheme, shared) {
			t.Errorf("a server accepts a client certificate that uses %v", scheme)
		}
	}
}

// TestClientListDoesNotChangeSharedList checks that the client list makes a new slice.
// An append to the array behind defaultSupportedSignatureAlgorithms would put ML-DSA in
// the server list as well.
func TestClientListDoesNotChangeSharedList(t *testing.T) {
	before := append([]SignatureScheme(nil), supportedSignatureAlgorithms()...)

	clientSupportedSignatureAlgorithms(VersionTLS13)

	after := supportedSignatureAlgorithms()
	if len(before) != len(after) {
		t.Fatalf("the shared list holds %d algorithms after the call, but held %d before",
			len(after), len(before))
	}
	for i := range before {
		if before[i] != after[i] {
			t.Errorf("the shared list changed at index %d: %v became %v", i, before[i], after[i])
		}
	}
}

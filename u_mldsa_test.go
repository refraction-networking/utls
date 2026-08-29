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

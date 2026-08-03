//go:build !nomldsa

package tls

import (
	"crypto"
	"strings"
	"testing"
)

func TestParseCertificatePatchesMLDSAPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		certPEM string
		keyPEM  string
		sigAlg  SignatureScheme
	}{
		{"MLDSA44", testMLDSA44CertPEM, testMLDSA44KeyPEM, MLDSA44},
		{"MLDSA65", testMLDSA65CertPEM, testMLDSA65KeyPEM, MLDSA65},
		{"MLDSA87", testMLDSA87CertPEM, testMLDSA87KeyPEM, MLDSA87},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cert, err := X509KeyPair([]byte(test.certPEM), []byte(testingKeyToPrivateKeyPEM(test.keyPEM)))
			if err != nil {
				t.Fatal(err)
			}
			if cert.Leaf == nil {
				t.Fatal("X509KeyPair did not set Leaf")
			}
			expectMLDSAPublicKey(t, cert.Leaf.PublicKey, test.sigAlg)
			if !isMLDSAPrivateKey(cert.PrivateKey) {
				t.Fatalf("PrivateKey = %T, want ML-DSA", cert.PrivateKey)
			}
			if !publicKeyMatchesMLDSAPrivateKey(cert.Leaf.PublicKey, cert.PrivateKey) {
				t.Fatal("ML-DSA public/private key mismatch")
			}
		})
	}
}

func expectMLDSAPublicKey(t *testing.T, pub crypto.PublicKey, want SignatureScheme) {
	t.Helper()

	got, ok := mldsaSignatureSchemeForPublicKey(pub)
	if !ok {
		t.Fatalf("PublicKey = %T, want ML-DSA", pub)
	}
	if got != want {
		t.Fatalf("ML-DSA signature scheme = %v, want %v", got, want)
	}
}

func testingKeyToPrivateKeyPEM(keyPEM string) string {
	keyPEM = strings.ReplaceAll(keyPEM, "BEGIN TESTING KEY", "BEGIN PRIVATE KEY")
	return strings.ReplaceAll(keyPEM, "END TESTING KEY", "END PRIVATE KEY")
}

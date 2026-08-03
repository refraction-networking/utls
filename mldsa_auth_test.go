//go:build !nomldsa

package tls

import (
	"crypto"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func TestLegacyTypeAndHashRejectsMLDSA(t *testing.T) {
	pub, _, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := legacyTypeAndHashFromPublicKey(pub); err == nil {
		t.Fatal("legacy signature path accepted ML-DSA")
	}
}

func TestMLDSACIRCLVerifyHandshakeSignature(t *testing.T) {
	tests := []struct {
		name string
		gen  func() (crypto.PublicKey, crypto.Signer, error)
	}{
		{
			name: "mldsa44",
			gen: func() (crypto.PublicKey, crypto.Signer, error) {
				pub, priv, err := mldsa44.GenerateKey(nil)
				return pub, priv, err
			},
		},
		{
			name: "mldsa65",
			gen: func() (crypto.PublicKey, crypto.Signer, error) {
				pub, priv, err := mldsa65.GenerateKey(nil)
				return pub, priv, err
			},
		},
		{
			name: "mldsa87",
			gen: func() (crypto.PublicKey, crypto.Signer, error) {
				pub, priv, err := mldsa87.GenerateKey(nil)
				return pub, priv, err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pub, priv, err := test.gen()
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("uTLS ML-DSA CertificateVerify input")
			sig, err := priv.Sign(nil, msg, crypto.Hash(0))
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyMLDSAHandshakeSignature(pub, msg, sig); err != nil {
				t.Fatalf("valid signature rejected: %v", err)
			}
			sig[0] ^= 0x80
			if err := verifyMLDSAHandshakeSignature(pub, msg, sig); err == nil {
				t.Fatal("invalid signature accepted")
			}
		})
	}
}

func TestVerifyHandshakeSignatureMLDSARequiresDirectSigning(t *testing.T) {
	pub, priv, err := mldsa44.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("uTLS ML-DSA CertificateVerify input")
	sig, err := priv.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyHandshakeSignature(signatureMLDSA, pub, crypto.SHA256, msg, sig); err == nil {
		t.Fatal("ML-DSA signature accepted with a pre-hash function")
	}
}

func TestSelectSignatureSchemeMLDSARequiresTLS13(t *testing.T) {
	cert, err := X509KeyPair([]byte(testMLDSA44CertPEM), []byte(testingKeyToPrivateKeyPEM(testMLDSA44KeyPEM)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := selectSignatureScheme(VersionTLS12, &cert, []SignatureScheme{MLDSA44}); err == nil {
		t.Fatal("TLS 1.2 selected ML-DSA signature scheme")
	}
	got, err := selectSignatureScheme(VersionTLS13, &cert, []SignatureScheme{MLDSA44})
	if err != nil {
		t.Fatal(err)
	}
	if got != MLDSA44 {
		t.Fatalf("selected %v, want %v", got, MLDSA44)
	}
}

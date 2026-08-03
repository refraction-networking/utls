//go:build nomldsa

package tls

import (
	"crypto"
	"crypto/x509"
	"errors"
)

func goMLDSASupported() bool {
	return false
}

func defaultMLDSASignatureAlgorithms() []SignatureScheme {
	return nil
}

func mldsaSignatureSchemeForPublicKey(pub crypto.PublicKey) (SignatureScheme, bool) {
	return 0, false
}

func isMLDSAPrivateKey(priv crypto.PrivateKey) bool {
	return false
}

func verifyMLDSAHandshakeSignature(pubkey crypto.PublicKey, signed, sig []byte) error {
	return errors.New("tls: ML-DSA support is disabled by the nomldsa build tag")
}

func parseCertificate(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

func parseMLDSAPrivateKey(der []byte) (crypto.PrivateKey, error) {
	return nil, errors.New("tls: ML-DSA support is disabled by the nomldsa build tag")
}

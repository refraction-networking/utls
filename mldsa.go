package tls

import (
	"crypto"
	"errors"
)

func isMLDSAPublicKey(pub crypto.PublicKey) bool {
	_, ok := mldsaSignatureSchemeForPublicKey(pub)
	return ok
}

func signatureSchemesForMLDSAPublicKey(version uint16, pub crypto.PublicKey) []SignatureScheme {
	if version != VersionTLS13 {
		return nil
	}
	if sigAlg, ok := mldsaSignatureSchemeForPublicKey(pub); ok {
		return []SignatureScheme{sigAlg}
	}
	return nil
}

func unsupportedMLDSACertificateError(pub crypto.PublicKey) error {
	if isMLDSAPublicKey(pub) {
		return errors.New("tls: ML-DSA certificates require TLS 1.3")
	}
	return nil
}

func publicKeyMatchesMLDSAPrivateKey(pub crypto.PublicKey, priv crypto.PrivateKey) bool {
	if pub == nil || priv == nil {
		return false
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return false
	}
	pubEq, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return pubEq.Equal(signer.Public())
}

//go:build !nomldsa

package tls

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	circlPki "github.com/cloudflare/circl/pki"
	circlSign "github.com/cloudflare/circl/sign"
	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

func goMLDSASupported() bool {
	return true
}

func defaultMLDSASignatureAlgorithms() []SignatureScheme {
	return []SignatureScheme{MLDSA44, MLDSA65, MLDSA87}
}

func mldsaSignatureSchemeForPublicKey(pub crypto.PublicKey) (SignatureScheme, bool) {
	switch pub.(type) {
	case *mldsa44.PublicKey:
		return MLDSA44, true
	case *mldsa65.PublicKey:
		return MLDSA65, true
	case *mldsa87.PublicKey:
		return MLDSA87, true
	}
	if pub, ok := pub.(circlSign.PublicKey); ok {
		switch pub.Scheme().Name() {
		case "ML-DSA-44":
			return MLDSA44, true
		case "ML-DSA-65":
			return MLDSA65, true
		case "ML-DSA-87":
			return MLDSA87, true
		}
	}
	return 0, false
}

func isMLDSAPrivateKey(priv crypto.PrivateKey) bool {
	switch priv.(type) {
	case *mldsa44.PrivateKey, *mldsa65.PrivateKey, *mldsa87.PrivateKey:
		return true
	}
	if priv, ok := priv.(circlSign.PrivateKey); ok {
		_, ok := mldsaSignatureSchemeForPublicKey(priv.Public())
		return ok
	}
	return false
}

func verifyMLDSAHandshakeSignature(pubkey crypto.PublicKey, signed, sig []byte) error {
	pub, ok := pubkey.(circlSign.PublicKey)
	if !ok {
		return fmt.Errorf("tls: expected ML-DSA public key, got %T", pubkey)
	}
	scheme := pub.Scheme()
	switch scheme.Name() {
	case "ML-DSA-44", "ML-DSA-65", "ML-DSA-87":
	default:
		return fmt.Errorf("tls: unsupported ML-DSA public key scheme %q", scheme.Name())
	}
	if !scheme.Verify(pub, signed, sig, nil) {
		return errors.New("tls: invalid ML-DSA signature")
	}
	return nil
}

// parseCertificate recognizes ML-DSA leaf public keys, but chain signatures
// still verify through crypto/x509, which has no ML-DSA support: only
// classically-issued ML-DSA leaf certificates pass verification.
func parseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	patchMLDSAPublicKey(cert)
	return cert, nil
}

func patchMLDSAPublicKey(cert *x509.Certificate) {
	if cert == nil || cert.PublicKey != nil || len(cert.RawSubjectPublicKeyInfo) == 0 {
		return
	}
	pub, err := circlPki.UnmarshalPKIXPublicKey(cert.RawSubjectPublicKeyInfo)
	if err != nil {
		return
	}
	if isMLDSAPublicKey(pub) {
		cert.PublicKey = pub
	}
}

func parseMLDSAPrivateKey(der []byte) (crypto.PrivateKey, error) {
	priv, err := circlPki.UnmarshalPKIXPrivateKey(der)
	if err != nil {
		return nil, err
	}
	if !isMLDSAPrivateKey(priv) {
		return nil, errors.New("tls: parsed CIRCL key is not ML-DSA")
	}
	return priv, nil
}

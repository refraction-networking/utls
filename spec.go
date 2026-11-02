// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/tls"

	itls "github.com/refraction-networking/utls/internal/tls"
)

// ClientHelloSpec fully describes the wire shape of a ClientHello: the cipher
// suites, compression methods, and the ordered list of extensions. A
// fingerprint is a function that returns one. Build your own for a custom
// fingerprint, or obtain one from a preset via ClientHelloID.Spec.
type ClientHelloSpec = itls.ClientHelloSpec

// TLSExtension is one ClientHello extension. Concrete types below cover the
// common extensions; GenericExtension carries anything else verbatim.
//
// The interface has unexported methods on purpose: new extension kinds are
// added inside uTLS (so they can wire into the handshake), while downstream
// composes the provided types and reaches for GenericExtension for the rest.
// This is deliberate — it is what lets the extension set evolve without
// breaking downstream, the central lesson of the v1 API.
type TLSExtension = itls.TLSExtension

// Concrete extension types, re-exported from the renderer.
type (
	SNIExtension                     = itls.SNIExtension
	SupportedVersionsExtension       = itls.SupportedVersionsExtension
	SupportedCurvesExtension         = itls.SupportedCurvesExtension
	SupportedPointsExtension         = itls.SupportedPointsExtension
	SignatureAlgorithmsExtension     = itls.SignatureAlgorithmsExtension
	SignatureAlgorithmsCertExtension = itls.SignatureAlgorithmsCertExtension
	ALPNExtension                    = itls.ALPNExtension
	ApplicationSettingsExtension     = itls.ApplicationSettingsExtension
	StatusRequestExtension           = itls.StatusRequestExtension
	SCTExtension                     = itls.SCTExtension
	ExtendedMasterSecretExtension    = itls.ExtendedMasterSecretExtension
	RenegotiationInfoExtension       = itls.RenegotiationInfoExtension
	SessionTicketExtension           = itls.SessionTicketExtension
	PSKKeyExchangeModesExtension     = itls.PSKKeyExchangeModesExtension
	CompressCertificateExtension     = itls.CompressCertificateExtension
	RecordSizeLimitExtension         = itls.RecordSizeLimitExtension
	KeyShareExtension                = itls.KeyShareExtension
	KeyShareEntry                    = itls.KeyShareEntry
	UtlsGREASEExtension              = itls.UtlsGREASEExtension
	UtlsPaddingExtension             = itls.UtlsPaddingExtension
	GenericExtension                 = itls.GenericExtension
)

// CertCompressionAlgo identifies a certificate compression algorithm (RFC 8879).
type CertCompressionAlgo = itls.CertCompressionAlgo

const (
	CertCompressionZlib   = itls.CertCompressionZlib
	CertCompressionBrotli = itls.CertCompressionBrotli
	CertCompressionZstd   = itls.CertCompressionZstd
)

// GREASE_PLACEHOLDER marks a slot (cipher, group, version, extension) that the
// renderer fills with a fresh GREASE value per connection (RFC 8701).
const GREASE_PLACEHOLDER = itls.GREASEPlaceholder

// BoringPaddingStyle is the default padding heuristic (BoringSSL's): pad the
// ClientHello to at least 512 bytes when it would otherwise be 256–511.
var BoringPaddingStyle = itls.BoringPaddingStyle

// Re-exported standard constants, so a spec reads naturally without importing
// crypto/tls alongside utls.
const (
	VersionTLS10 = tls.VersionTLS10
	VersionTLS11 = tls.VersionTLS11
	VersionTLS12 = tls.VersionTLS12
	VersionTLS13 = tls.VersionTLS13
)

// Named groups (uTLS-typed, sourced from the internal mirror so they match the
// extension field types).
const (
	X25519         CurveID = itls.X25519
	CurveP256      CurveID = itls.CurveP256
	CurveP384      CurveID = itls.CurveP384
	CurveP521      CurveID = itls.CurveP521
	X25519MLKEM768 CurveID = itls.X25519MLKEM768
)

// Signature schemes (subset commonly used in fingerprints).
const (
	PKCS1WithSHA256        SignatureScheme = itls.PKCS1WithSHA256
	PKCS1WithSHA384        SignatureScheme = itls.PKCS1WithSHA384
	PKCS1WithSHA512        SignatureScheme = itls.PKCS1WithSHA512
	PSSWithSHA256          SignatureScheme = itls.PSSWithSHA256
	PSSWithSHA384          SignatureScheme = itls.PSSWithSHA384
	PSSWithSHA512          SignatureScheme = itls.PSSWithSHA512
	ECDSAWithP256AndSHA256 SignatureScheme = itls.ECDSAWithP256AndSHA256
	ECDSAWithP384AndSHA384 SignatureScheme = itls.ECDSAWithP384AndSHA384
	ECDSAWithP521AndSHA512 SignatureScheme = itls.ECDSAWithP521AndSHA512
	Ed25519                SignatureScheme = itls.Ed25519
	PKCS1WithSHA1          SignatureScheme = itls.PKCS1WithSHA1
	ECDSAWithSHA1          SignatureScheme = itls.ECDSAWithSHA1
)

// Cipher suite IDs commonly used in fingerprints (re-exported from crypto/tls).
const (
	TLS_AES_128_GCM_SHA256                        = tls.TLS_AES_128_GCM_SHA256
	TLS_AES_256_GCM_SHA384                        = tls.TLS_AES_256_GCM_SHA384
	TLS_CHACHA20_POLY1305_SHA256                  = tls.TLS_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
	TLS_RSA_WITH_AES_128_GCM_SHA256               = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	TLS_RSA_WITH_AES_256_GCM_SHA384               = tls.TLS_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	TLS_RSA_WITH_AES_128_CBC_SHA                  = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	TLS_RSA_WITH_AES_256_CBC_SHA                  = tls.TLS_RSA_WITH_AES_256_CBC_SHA
)

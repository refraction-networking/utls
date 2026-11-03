// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/tls"
	"time"

	itls "github.com/refraction-networking/utls/internal/tls"
)

// ClientHelloSpec describes a ClientHello's shape; see the type documentation
// in internal/tls for how a spec and the Config combine (versions, cipher
// suites, groups, ALPN, SNI, session tickets). Specs are copied when attached
// to a connection.
type ClientHelloSpec = itls.ClientHelloSpec

// TLSExtension is one ClientHello extension slot. Its methods are unexported:
// extension kinds are defined by uTLS (so they integrate with the handshake);
// use GenericExtension for opaque extensions.
type TLSExtension = itls.TLSExtension

// Extension types. Handshake-owned content (SNI name, key shares, PSK, cookie,
// ECH payload, session ticket) is always rendered from the live handshake.
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
	EncryptedClientHelloExtension    = itls.EncryptedClientHelloExtension
	HPKESymmetricCipherSuite         = itls.HPKESymmetricCipherSuite
	PreSharedKeyExtension            = itls.PreSharedKeyExtension
	EarlyDataExtension               = itls.EarlyDataExtension
	CookieExtension                  = itls.CookieExtension
	QUICTransportParametersExtension = itls.QUICTransportParametersExtension
	TrustAnchorsExtension            = itls.TrustAnchorsExtension
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

// ALPS code points for ApplicationSettingsExtension.CodePoint.
const (
	ALPSCodepointOld uint16 = 17513
	ALPSCodepointNew uint16 = 17613
)

// GREASE_PLACEHOLDER marks a slot (cipher, group, version, signature scheme,
// key share) the renderer fills with a per-connection GREASE value.
const GREASE_PLACEHOLDER = itls.GREASEPlaceholder

// BoringPaddingStyle is BoringSSL's padding heuristic.
var BoringPaddingStyle = itls.BoringPaddingStyle

const (
	VersionTLS10 = tls.VersionTLS10
	VersionTLS11 = tls.VersionTLS11
	VersionTLS12 = tls.VersionTLS12
	VersionTLS13 = tls.VersionTLS13
)

const (
	X25519         CurveID = itls.X25519
	CurveP256      CurveID = itls.CurveP256
	CurveP384      CurveID = itls.CurveP384
	CurveP521      CurveID = itls.CurveP521
	X25519MLKEM768 CurveID = itls.X25519MLKEM768
)

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
	MLDSA44                SignatureScheme = itls.MLDSA44
	MLDSA65                SignatureScheme = itls.MLDSA65
	MLDSA87                SignatureScheme = itls.MLDSA87
)

const (
	TLS_AES_128_GCM_SHA256                        = tls.TLS_AES_128_GCM_SHA256
	TLS_AES_256_GCM_SHA384                        = tls.TLS_AES_256_GCM_SHA384
	TLS_CHACHA20_POLY1305_SHA256                  = tls.TLS_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       = tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         = tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       = tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         = tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_RSA_WITH_AES_128_GCM_SHA256               = tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	TLS_RSA_WITH_AES_256_GCM_SHA384               = tls.TLS_RSA_WITH_AES_256_GCM_SHA384
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          = tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            = tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       = tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         = tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	TLS_RSA_WITH_AES_128_CBC_SHA                  = tls.TLS_RSA_WITH_AES_128_CBC_SHA
	TLS_RSA_WITH_AES_256_CBC_SHA                  = tls.TLS_RSA_WITH_AES_256_CBC_SHA
	TLS_RSA_WITH_AES_128_CBC_SHA256               = tls.TLS_RSA_WITH_AES_128_CBC_SHA256
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           = tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 = tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA
)

// ClientSessionParams describes a session to resume out of band (for example a
// ticket a server will accept because both sides derive it from a shared
// secret). Version is VersionTLS12 or VersionTLS13.
//
//   - TLS 1.2: Secret is the 48-byte master secret; Ticket the session ticket.
//   - TLS 1.3: Secret is the resumption PSK (hash-size bytes); Ticket the PSK
//     identity; AgeAdd the ticket_age_add.
type ClientSessionParams struct {
	Version              uint16
	CipherSuite          uint16
	Secret               []byte
	Ticket               []byte
	ExtendedMasterSecret bool
	CreatedAt            time.Time
	AgeAdd               uint32
	Lifetime             time.Duration
}

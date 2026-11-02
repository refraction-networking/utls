// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file holds the built-in fingerprint presets. Each is a function that
// returns a FRESH ClientHelloSpec, registered under canonical names and
// aliases. To add or update a fingerprint, add a builder here and register it;
// see docs/FINGERPRINTS.md for the full procedure and fidelity caveats.

package utls

// HelloGolang sends the standard crypto/tls ClientHello (no fingerprinting).
// It carries no spec; the connection falls through to stock crypto/tls.
var HelloGolang = register(ClientHelloID{Client: "Golang", Version: "Auto"}, "golang", "go")

// HelloCustom is an empty fingerprint. Use it with UClient and then call
// (*UConn).ApplyPreset with your own ClientHelloSpec.
var HelloCustom = ClientHelloID{Client: "Custom", Version: "Auto"}

// HelloChrome_Auto mimics a current Chrome/Chromium TLS ClientHello.
var HelloChrome_Auto = register(
	ClientHelloID{Client: "Chrome", Version: "Auto", specFactory: chromeSpec},
	"chrome", "chromium", "chrome_pq", "chrome_psk",
)

// HelloEdge_Auto is Chromium-based; it shares Chrome's TLS fingerprint.
var HelloEdge_Auto = register(
	ClientHelloID{Client: "Edge", Version: "Auto", specFactory: chromeSpec},
	"edge",
)

// HelloFirefox_Auto mimics a current Firefox TLS ClientHello.
var HelloFirefox_Auto = register(
	ClientHelloID{Client: "Firefox", Version: "Auto", specFactory: firefoxSpec},
	"firefox",
)

// HelloSafari_Auto mimics a current Safari (Apple) TLS ClientHello.
var HelloSafari_Auto = register(
	ClientHelloID{Client: "Safari", Version: "Auto", specFactory: safariSpec},
	"safari",
)

// HelloIOS_Auto shares Safari's TLS stack on iOS.
var HelloIOS_Auto = register(
	ClientHelloID{Client: "iOS", Version: "Auto", specFactory: safariSpec},
	"ios",
)

func chromeSpec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&SessionTicketExtension{},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
				ECDSAWithP384AndSHA384, PSSWithSHA384, PKCS1WithSHA384,
				PSSWithSHA512, PKCS1WithSHA512,
			}},
			&SCTExtension{},
			&KeyShareExtension{KeyShares: []KeyShareEntry{
				{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: X25519MLKEM768},
				{Group: X25519},
			}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
			&CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
			&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
			&UtlsGREASEExtension{Body: []byte{0}},
			&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
		},
	}, nil
}

func firefoxSpec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&SessionTicketExtension{},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&KeyShareExtension{KeyShares: []KeyShareEntry{
				{Group: X25519MLKEM768},
				{Group: X25519},
			}},
			&SupportedVersionsExtension{Versions: []uint16{VersionTLS13, VersionTLS12}},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384, ECDSAWithP521AndSHA512,
				PSSWithSHA256, PSSWithSHA384, PSSWithSHA512,
				PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512,
				ECDSAWithSHA1, PKCS1WithSHA1,
			}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&RecordSizeLimitExtension{Limit: 0x4001},
			&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
		},
	}, nil
}

func safariSpec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_128_GCM_SHA256,
			TLS_AES_256_GCM_SHA384,
			TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384, CurveP521}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
				ECDSAWithP384AndSHA384, ECDSAWithSHA1, PSSWithSHA384,
				PKCS1WithSHA384, PSSWithSHA512, PKCS1WithSHA512, PKCS1WithSHA1,
			}},
			&SCTExtension{},
			&KeyShareExtension{KeyShares: []KeyShareEntry{
				{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}},
				{Group: X25519},
			}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
			&CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
			&UtlsGREASEExtension{Body: []byte{0}},
			&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
		},
	}, nil
}

// pskModeDHE mirrors the internal constant so specs can request psk_dhe_ke
// without importing internal/tls.
const pskModeDHE uint8 = 1

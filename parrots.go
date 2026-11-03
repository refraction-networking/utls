// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Built-in fingerprint presets. Each factory returns a FRESH spec.
//
// Provenance (see docs/FINGERPRINTS.md):
//   - Chrome 155: checked against an independent capture of Google Chrome
//     155.0.8059.40 (testdata/chrome155_clienthello.hex, chrome155_test.go).
//   - Firefox 158: checked against isolated loopback captures of Mozilla
//     Firefox 158.0 (testdata/firefox158_clienthello*.hex, fidelity_test.go).
//   - Firefox 148, Safari 26.3, iOS 14, Android 11 OkHttp, QQ 11.1: ported
//     unchanged from uTLS v1 (refraction-networking/utls ff1b50f, u_parrots.go),
//     where they were derived from captures; no capture is bundled here, so
//     their tests check structure and interoperability, not browser equality.
//   - Edge: Chromium-based; uses the Chrome 155 profile.

package utls

import (
	crand "crypto/rand"
	"math/rand/v2"
)

var (
	// HelloGolang sends the stock crypto/tls ClientHello (no fingerprinting).
	HelloGolang = register(ClientHelloID{Client: "Golang", Version: "Auto", kind: kindGolang}, "golang", "go")

	// HelloCustom sends the spec given to (*UConn).ApplyPreset; the handshake
	// fails with ErrNoSpec without one.
	HelloCustom = ClientHelloID{Client: "Custom", Version: "Auto", kind: kindCustom}

	HelloChrome_155  = register(preset("Chrome", "155", chrome155Spec), "chrome155")
	HelloChrome_Auto = register(withVersion(HelloChrome_155, "Auto"), "chrome", "chromium", "chrome_pq")
	HelloEdge_Auto   = register(preset("Edge", "Auto", chrome155Spec), "edge")

	HelloFirefox_148  = register(preset("Firefox", "148", firefox148Spec), "firefox148")
	HelloFirefox_158  = register(preset("Firefox", "158", firefox158Spec), "firefox158")
	HelloFirefox_Auto = register(withVersion(HelloFirefox_158, "Auto"), "firefox")

	HelloSafari_26_3 = register(preset("Safari", "26.3", safari263Spec), "safari26")
	HelloSafari_Auto = register(withVersion(HelloSafari_26_3, "Auto"), "safari")

	HelloIOS_14   = register(preset("iOS", "14", ios14Spec), "ios14")
	HelloIOS_Auto = register(withVersion(HelloIOS_14, "Auto"), "ios")

	HelloAndroid_11_OkHttp = register(preset("Android", "11-OkHttp", android11OkHttpSpec), "android", "okhttp")

	HelloQQ_11_1 = register(preset("QQ", "11.1", qq111Spec), "qq111")
	HelloQQ_Auto = register(withVersion(HelloQQ_11_1, "Auto"), "qq")
)

func withVersion(id ClientHelloID, v string) ClientHelloID {
	id.Version = v
	return id
}

const pskModeDHE uint8 = 1

// shuffleChromeExtensions permutes extensions as Chrome 106+ does, keeping
// GREASE, padding and pre_shared_key in place.
func shuffleChromeExtensions(exts []TLSExtension) []TLSExtension {
	var seed [32]byte
	crand.Read(seed[:])
	r := rand.New(rand.NewChaCha8(seed))
	fixed := func(e TLSExtension) bool {
		switch e.(type) {
		case *UtlsGREASEExtension, *UtlsPaddingExtension, *PreSharedKeyExtension:
			return true
		}
		return false
	}
	var idx []int
	for i, e := range exts {
		if !fixed(e) {
			idx = append(idx, i)
		}
	}
	perm := r.Perm(len(idx))
	out := make([]TLSExtension, len(exts))
	copy(out, exts)
	for i, p := range perm {
		out[idx[i]] = exts[idx[p]]
	}
	return out
}

// chrome155TrustAnchorIDs are the Chrome Root Store IDs advertised by Chrome
// 155.0.8059.40, in Chrome's (lexicographic) order.
// Source: https://chromium.googlesource.com/chromium/src/+/refs/tags/155.0.8059.40/net/data/ssl/chrome_root_store/root_store.textproto
func chrome155TrustAnchorIDs() [][]byte {
	return [][]byte{
		{0x82, 0xdf, 0x13, 0x02, 0x01}, {0x82, 0xdf, 0x13, 0x02, 0x06}, {0x82, 0xdf, 0x13, 0x02, 0x0d},
		{0x82, 0xdf, 0x13, 0x02, 0x0e}, {0x82, 0xdf, 0x13, 0x02, 0x0f}, {0x82, 0xdf, 0x13, 0x02, 0x12},
		{0x82, 0xdf, 0x13, 0x02, 0x13}, {0x82, 0xdf, 0x13, 0x02, 0x14},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07}, {0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09}, {0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b}, {0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d}, {0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12},
		{0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13},
		{0xd6, 0x79, 0x09, 0x01}, {0xd6, 0x79, 0x09, 0x04}, {0xd6, 0x79, 0x09, 0x05}, {0xd6, 0x79, 0x09, 0x06},
		{0xd6, 0x79, 0x09, 0x07}, {0xd6, 0x79, 0x09, 0x08}, {0xd6, 0x79, 0x09, 0x0a}, {0xd6, 0x79, 0x09, 0x0b},
		{0xd6, 0x79, 0x09, 0x0c}, {0xd6, 0x79, 0x09, 0x0d}, {0xd6, 0x79, 0x09, 0x0f},
	}
}

func chrome155Spec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: shuffleChromeExtensions([]TLSExtension{
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
				GREASE_PLACEHOLDER, MLDSA44, MLDSA65, MLDSA87,
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
			&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}, CodePoint: ALPSCodepointNew},
			&TrustAnchorsExtension{TrustAnchorIDs: chrome155TrustAnchorIDs()},
			&EncryptedClientHelloExtension{GREASE: true},
			&UtlsGREASEExtension{Body: []byte{0}},
		}),
	}, nil
}

func firefox148Spec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521, 0x0100, 0x0101}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			// delegated_credentials: ECDSA P-256/384/521, ECDSA-SHA1
			&GenericExtension{Id: 34, Data: []byte{0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03}},
			&SCTExtension{},
			&KeyShareExtension{ReuseClassicalFromHybrid: true, KeyShares: []KeyShareEntry{
				{Group: X25519MLKEM768}, {Group: X25519}, {Group: CurveP256},
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
			&CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib, CertCompressionBrotli, CertCompressionZstd}},
			&EncryptedClientHelloExtension{
				GREASE:               true,
				GREASECipherSuites:   []HPKESymmetricCipherSuite{{KDF: 1, AEAD: 1}, {KDF: 1, AEAD: 3}},
				GREASEPayloadLengths: []uint16{239},
			},
		},
	}, nil
}

// firefox158Spec reproduces Mozilla Firefox 158.0 (macOS) as captured on
// loopback (testdata/firefox158_clienthello.md). Relative to 148 it drops the
// ECDHE-ECDSA-AES-CBC suites and the FFDHE groups, adds session_ticket and
// sends a 240-byte GREASE ECH payload with HKDF-SHA256/ChaCha20-Poly1305.
func firefox158Spec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA,
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
			// delegated_credentials: ECDSA P-256/384/521, ECDSA-SHA1
			&GenericExtension{Id: 34, Data: []byte{0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03}},
			&SCTExtension{},
			&KeyShareExtension{ReuseClassicalFromHybrid: true, KeyShares: []KeyShareEntry{
				{Group: X25519MLKEM768}, {Group: X25519}, {Group: CurveP256},
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
			&CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib, CertCompressionBrotli, CertCompressionZstd}},
			&EncryptedClientHelloExtension{
				GREASE:               true,
				GREASECipherSuites:   []HPKESymmetricCipherSuite{{KDF: 1, AEAD: 3}},
				GREASEPayloadLengths: []uint16{240},
			},
		},
	}, nil
}

func safari263Spec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		TLSVersMin: VersionTLS12,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256,
			TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA,
			0xc008, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{GREASE_PLACEHOLDER, X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
				ECDSAWithP384AndSHA384, PSSWithSHA384, PSSWithSHA384, PKCS1WithSHA384,
				PSSWithSHA512, PKCS1WithSHA512, PKCS1WithSHA1,
			}},
			&SCTExtension{},
			&KeyShareExtension{KeyShares: []KeyShareEntry{
				{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}}, {Group: X25519MLKEM768}, {Group: X25519},
			}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12}},
			&CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionZlib}},
			&UtlsGREASEExtension{},
		},
	}, nil
}

func ios14Spec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			0xc024, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			0xc028, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			TLS_RSA_WITH_AES_256_GCM_SHA384, TLS_RSA_WITH_AES_128_GCM_SHA256,
			0x003d, TLS_RSA_WITH_AES_128_CBC_SHA256, TLS_RSA_WITH_AES_256_CBC_SHA, TLS_RSA_WITH_AES_128_CBC_SHA,
			0xc008, TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, TLS_RSA_WITH_3DES_EDE_CBC_SHA,
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
				ECDSAWithP384AndSHA384, ECDSAWithSHA1, PSSWithSHA384, PSSWithSHA384,
				PKCS1WithSHA384, PSSWithSHA512, PKCS1WithSHA512, PKCS1WithSHA1,
			}},
			&SCTExtension{},
			&KeyShareExtension{KeyShares: []KeyShareEntry{{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}}, {Group: X25519}}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12, VersionTLS11, VersionTLS10}},
			&UtlsGREASEExtension{},
			&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
		},
	}, nil
}

func android11OkHttpSpec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		CipherSuites: []uint16{
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{X25519, CurveP256, CurveP384}},
			&SupportedPointsExtension{SupportedPoints: []uint8{0}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []SignatureScheme{
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256,
				ECDSAWithP384AndSHA384, PSSWithSHA384, PKCS1WithSHA384,
				PSSWithSHA512, PKCS1WithSHA512, PKCS1WithSHA1,
			}},
		},
	}, nil
}

func qq111Spec() (*ClientHelloSpec, error) {
	return &ClientHelloSpec{
		TLSVersMin: VersionTLS10,
		TLSVersMax: VersionTLS13,
		CipherSuites: []uint16{
			GREASE_PLACEHOLDER,
			TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			TLS_RSA_WITH_AES_128_GCM_SHA256, TLS_RSA_WITH_AES_256_GCM_SHA384,
			TLS_RSA_WITH_AES_128_CBC_SHA, TLS_RSA_WITH_AES_256_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{Curves: []CurveID{GREASE_PLACEHOLDER, X25519, CurveP256, CurveP384}},
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
			&KeyShareExtension{KeyShares: []KeyShareEntry{{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}}, {Group: X25519}}},
			&PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}},
			&SupportedVersionsExtension{Versions: []uint16{GREASE_PLACEHOLDER, VersionTLS13, VersionTLS12, VersionTLS11, VersionTLS10}},
			&CompressCertificateExtension{Algorithms: []CertCompressionAlgo{CertCompressionBrotli}},
			&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}},
			&UtlsGREASEExtension{},
			&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
		},
	}, nil
}

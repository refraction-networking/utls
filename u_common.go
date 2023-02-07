// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"hash"
)

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Things, supported by utls, but not crypto/tls' are prefixed with "utls"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.

// TLS handshake message types.
const (
	utlsTypeEncryptedExtensions uint8 = 8 // implemention incomplete by crypto/tls
	// https://datatracker.ietf.org/doc/html/rfc8879#section-7.2
	utlsTypeCompressedCertificate uint8 = 25
)

// TLS
const (
	utlsExtensionPadding              uint16 = 21
	utlsExtensionExtendedMasterSecret uint16 = 23    // https://tools.ietf.org/html/rfc7627
	utlsExtensionCompressCertificate  uint16 = 27    // https://datatracker.ietf.org/doc/html/rfc8879#section-7.1
	utlsExtensionApplicationSettings  uint16 = 17513 // not IANA assigned
	utlsFakeExtensionCustom           uint16 = 1234  // not IANA assigned, for ALPS

	// extensions with 'fake' prefix break connection, if server echoes them back
	fakeExtensionTokenBinding         uint16 = 24
	fakeOldExtensionChannelID         uint16 = 30031 // not IANA assigned
	fakeExtensionChannelID            uint16 = 30032 // not IANA assigned
	fakeExtensionDelegatedCredentials uint16 = 34
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA    = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA    = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5            = uint16(0x0004)
	FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = uint16(0x009f)
	FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA    = uint16(0x0032)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = uint16(0x006b)
	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = uint16(0x0067)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV   = uint16(0x00ff)

	// https://docs.microsoft.com/en-us/dotnet/api/system.net.security.tlsciphersuite?view=netcore-3.1
	FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = uint16(0xc008)
)

// Other things
const (
	fakeRecordSizeLimit uint16 = 0x001c
)

// newest signatures
var (
	FakePKCS1WithSHA224 SignatureScheme = 0x0301
	FakeECDSAWithSHA224 SignatureScheme = 0x0303

	FakeSHA1WithDSA   SignatureScheme = 0x0202
	FakeSHA256WithDSA SignatureScheme = 0x0402

	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

// fake curves(groups)
var (
	FakeFFDHE2048 = uint16(0x0100)
	FakeFFDHE3072 = uint16(0x0101)
)

// https://tools.ietf.org/html/draft-ietf-tls-certificate-compression-04
type CertCompressionAlgo uint16

const (
	CertCompressionZlib   CertCompressionAlgo = 0x0001
	CertCompressionBrotli CertCompressionAlgo = 0x0002
	CertCompressionZstd   CertCompressionAlgo = 0x0003
)

const (
	PskModePlain uint8 = pskModePlain
	PskModeDHE   uint8 = pskModeDHE
)

type ClientHelloID struct {
	Client string

	// Version specifies version of a mimicked clients (e.g. browsers).
	// Not used in randomized, custom handshake, and default Go.
	Version string

	// Seed is only used for randomized fingerprints to seed PRNG.
	// Must not be modified once set.
	Seed *PRNGSeed

	// Weights are only used for randomized fingerprints in func
	// generateRandomizedSpec(). Must not be modified once set.
	Weights *Weights
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%s", p.Client, p.Version)
}

func (p *ClientHelloID) IsSet() bool {
	return (p.Client == "") && (p.Version == "")
}

const (
	// clients
	helloGolang           = "Golang"
	helloRandomized       = "Randomized"
	helloRandomizedALPN   = "Randomized-ALPN"
	helloRandomizedNoALPN = "Randomized-NoALPN"
	helloCustom           = "Custom"
	helloFirefox          = "Firefox"
	helloChrome           = "Chrome"
	helloIOS              = "iOS"
	helloAndroid          = "Android"
	helloEdge             = "Edge"
	helloSafari           = "Safari"
	hello360              = "360Browser"
	helloQQ               = "QQBrowser"

	// versions
	helloAutoVers = "0"
)

type ClientHelloSpec struct {
	CipherSuites       []uint16       // nil => default
	CompressionMethods []uint8        // nil => no compression
	Extensions         []TLSExtension // nil => no extensions

	TLSVersMin uint16 // [1.0-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.0
	TLSVersMax uint16 // [1.2-1.3] default: parse from .Extensions, if SupportedVersions ext is not present => 1.2

	// GreaseStyle: currently only random
	// sessionID may or may not depend on ticket; nil => random
	GetSessionID func(ticket []byte) [32]byte

	// TLSFingerprintLink string // ?? link to tlsfingerprint.io for informational purposes
}

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang = ClientHelloID{helloGolang, helloAutoVers, nil, nil}

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with
	// TLSExtensions manually or use ApplyPreset function
	HelloCustom = ClientHelloID{helloCustom, helloAutoVers, nil, nil}

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       = ClientHelloID{helloRandomized, helloAutoVers, nil, nil}
	HelloRandomizedALPN   = ClientHelloID{helloRandomizedALPN, helloAutoVers, nil, nil}
	HelloRandomizedNoALPN = ClientHelloID{helloRandomizedNoALPN, helloAutoVers, nil, nil}

	// The rest will will parrot given browser.
	HelloFirefox_Auto = HelloFirefox_105
	HelloFirefox_55   = ClientHelloID{helloFirefox, "55", nil, nil}
	HelloFirefox_56   = ClientHelloID{helloFirefox, "56", nil, nil}
	HelloFirefox_63   = ClientHelloID{helloFirefox, "63", nil, nil}
	HelloFirefox_65   = ClientHelloID{helloFirefox, "65", nil, nil}
	HelloFirefox_99   = ClientHelloID{helloFirefox, "99", nil, nil}
	HelloFirefox_102  = ClientHelloID{helloFirefox, "102", nil, nil}
	HelloFirefox_105  = ClientHelloID{helloFirefox, "105", nil, nil}

	HelloChrome_Auto        = HelloChrome_106_Shuffle
	HelloChrome_58          = ClientHelloID{helloChrome, "58", nil, nil}
	HelloChrome_62          = ClientHelloID{helloChrome, "62", nil, nil}
	HelloChrome_70          = ClientHelloID{helloChrome, "70", nil, nil}
	HelloChrome_72          = ClientHelloID{helloChrome, "72", nil, nil}
	HelloChrome_83          = ClientHelloID{helloChrome, "83", nil, nil}
	HelloChrome_87          = ClientHelloID{helloChrome, "87", nil, nil}
	HelloChrome_96          = ClientHelloID{helloChrome, "96", nil, nil}
	HelloChrome_100         = ClientHelloID{helloChrome, "100", nil, nil}
	HelloChrome_102         = ClientHelloID{helloChrome, "102", nil, nil}
	HelloChrome_106_Shuffle = ClientHelloID{helloChrome, "106", nil, nil} // beta: shuffler enabled starting from 106

	HelloIOS_Auto = HelloIOS_14
	HelloIOS_11_1 = ClientHelloID{helloIOS, "111", nil, nil} // legacy "111" means 11.1
	HelloIOS_12_1 = ClientHelloID{helloIOS, "12.1", nil, nil}
	HelloIOS_13   = ClientHelloID{helloIOS, "13", nil, nil}
	HelloIOS_14   = ClientHelloID{helloIOS, "14", nil, nil}

	HelloAndroid_11_OkHttp = ClientHelloID{helloAndroid, "11", nil, nil}

	HelloEdge_Auto = HelloEdge_85 // HelloEdge_106 seems to be incompatible with this library
	HelloEdge_85   = ClientHelloID{helloEdge, "85", nil, nil}
	HelloEdge_106  = ClientHelloID{helloEdge, "106", nil, nil}

	HelloSafari_Auto = HelloSafari_16_0
	HelloSafari_16_0 = ClientHelloID{helloSafari, "16.0", nil, nil}

	Hello360_Auto = Hello360_7_5 // Hello360_11_0 seems to be incompatible with this library
	Hello360_7_5  = ClientHelloID{hello360, "7.5", nil, nil}
	Hello360_11_0 = ClientHelloID{hello360, "11.0", nil, nil}

	HelloQQ_Auto = HelloQQ_11_1
	HelloQQ_11_1 = ClientHelloID{helloQQ, "11.1", nil, nil}
)

type Weights struct {
	Extensions_Append_ALPN                             float64
	TLSVersMax_Set_VersionTLS13                        float64
	CipherSuites_Remove_RandomCiphers                  float64
	SigAndHashAlgos_Append_ECDSAWithSHA1               float64
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512      float64
	SigAndHashAlgos_Append_PSSWithSHA256               float64
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512 float64
	CurveIDs_Append_X25519                             float64
	CurveIDs_Append_CurveP521                          float64
	Extensions_Append_Padding                          float64
	Extensions_Append_Status                           float64
	Extensions_Append_SCT                              float64
	Extensions_Append_Reneg                            float64
	Extensions_Append_EMS                              float64
	FirstKeyShare_Set_CurveP256                        float64
	Extensions_Append_ALPS                             float64
}

// Do not modify them directly as they may being used. If you
// want to use your custom weights, please make a copy first.
var DefaultWeights = Weights{
	Extensions_Append_ALPN:                             0.7,
	TLSVersMax_Set_VersionTLS13:                        0.4,
	CipherSuites_Remove_RandomCiphers:                  0.4,
	SigAndHashAlgos_Append_ECDSAWithSHA1:               0.63,
	SigAndHashAlgos_Append_ECDSAWithP521AndSHA512:      0.59,
	SigAndHashAlgos_Append_PSSWithSHA256:               0.51,
	SigAndHashAlgos_Append_PSSWithSHA384_PSSWithSHA512: 0.9,
	CurveIDs_Append_X25519:                             0.71,
	CurveIDs_Append_CurveP521:                          0.46,
	Extensions_Append_Padding:                          0.62,
	Extensions_Append_Status:                           0.74,
	Extensions_Append_SCT:                              0.46,
	Extensions_Append_Reneg:                            0.75,
	Extensions_Append_EMS:                              0.77,
	FirstKeyShare_Set_CurveP256:                        0.25,
	Extensions_Append_ALPS:                             0.33,
}

// based on spec's GreaseStyle, GREASE_PLACEHOLDER may be replaced by another GREASE value
// https://tools.ietf.org/html/draft-ietf-tls-grease-01
const GREASE_PLACEHOLDER = 0x0a0a

func isGREASEUint16(v uint16) bool {
	// First byte is same as second byte
	// and lowest nibble is 0xa
	return ((v >> 8) == v&0xff) && v&0xf == 0xa
}

func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASE_PLACEHOLDER
	} else {
		return v
	}
}

// utlsMacSHA384 returns a SHA-384 based MAC. These are only supported in TLS 1.2
// so the given version is ignored.
func utlsMacSHA384(key []byte) hash.Hash {
	return hmac.New(sha512.New384, key)
}

var utlsSupportedCipherSuites []*cipherSuite

func init() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
		{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
	}...)
}

// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
// This provides better compatibility with servers on the web, but weakens security. Feel free
// to use this option if you establish additional secure connection inside of utls connection.
// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
// Must be called before establishing any connections.
func EnableWeakCiphers() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
			suiteTLS12, cipherAES, macSHA256, nil},

		{DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
			suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
		{DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	}...)
}

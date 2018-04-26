// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
)

// Naming convention:
// Unsupported things are prefixed with "Fake"
// Things, supported by utls, but not crypto/tls' are prefixed with "utls"
// Supported things, that have changed their ID are prefixed with "Old"
// Supported but disabled things are prefixed with "Disabled". We will _enable_ them.
const (
	utlsExtensionPadding              uint16 = 21
	utlsExtensionExtendedMasterSecret uint16 = 23 // https://tools.ietf.org/html/rfc7627

	// extensions with 'fake' prefix break connection, if server echoes them back
	fakeExtensionChannelID uint16 = 30032 // not IANA assigned
)

const (
	OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   = uint16(0xcc13)
	OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc14)

	DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = uint16(0xc024)
	DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384   = uint16(0xc028)
	DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256         = uint16(0x003d)

	FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = uint16(0xcc15) // we can try to craft these ciphersuites
	FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256           = uint16(0x009e) // from existing pieces, if needed

	FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA  = uint16(0x0033)
	FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA  = uint16(0x0039)
	FAKE_TLS_RSA_WITH_RC4_128_MD5          = uint16(0x0004)
	FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV = uint16(0x00ff)
)

// newest signatures
var (
	fakeRsaPssSha256 = SignatureAndHash{0x08, 0x04} // also declared in common.go as type SignatureScheme,
	fakeRsaPssSha384 = SignatureAndHash{0x08, 0x05} // but not used by default and not implemented
	fakeRsaPssSha512 = SignatureAndHash{0x08, 0x06}
	// fakeEd25519 = SignatureAndHash{0x08, 0x07}
	// fakeEd448 = SignatureAndHash{0x08, 0x08}
)

// IDs of hash functions in signatures
const (
	disabledHashSHA512 uint8 = 6 // Supported, but disabled by default. Will be enabled, as needed
	fakeHashSHA224     uint8 = 3 // Supported, but we won't enable it: sounds esoteric and fishy
)

type ClientHelloID struct {
	Browser string
	Version uint16
	// TODO: consider adding OS?
}

func (p *ClientHelloID) Str() string {
	return fmt.Sprintf("%s-%d", p.Browser, p.Version)
}

const (
	helloGolang     = "Golang"
	helloRandomized = "Randomized"
	helloCustom     = "Custom"
	helloFirefox    = "Firefox"
	helloChrome     = "Chrome"
	helloAndroid    = "Android"
)

const (
	helloAutoVers = iota
	helloRandomizedALPN
	helloRandomizedNoALPN
)

var (
	// HelloGolang will use default "crypto/tls" handshake marshaling codepath, which WILL
	// overwrite your changes to Hello(Config, Session are fine).
	// You might want to call BuildHandshakeState() before applying any changes.
	// UConn.Extensions will be completely ignored.
	HelloGolang ClientHelloID = ClientHelloID{helloGolang, helloAutoVers}

	// HelloCustom will prepare ClientHello with empty uconn.Extensions so you can fill it with TLSExtension's manually
	HelloCustom ClientHelloID = ClientHelloID{helloCustom, helloAutoVers}

	// HelloRandomized* randomly adds/reorders extensions, ciphersuites, etc.
	HelloRandomized       ClientHelloID = ClientHelloID{helloRandomized, helloAutoVers}
	HelloRandomizedALPN   ClientHelloID = ClientHelloID{helloRandomized, helloRandomizedALPN}
	HelloRandomizedNoALPN ClientHelloID = ClientHelloID{helloRandomized, helloRandomizedNoALPN}

	// The rest will will parrot given browser.
	HelloFirefox_Auto ClientHelloID = ClientHelloID{helloFirefox, helloAutoVers}
	HelloFirefox_55                 = ClientHelloID{helloFirefox, 55}
	HelloFirefox_56                 = ClientHelloID{helloFirefox, 56}

	HelloChrome_Auto ClientHelloID = ClientHelloID{helloChrome, helloAutoVers}
	HelloChrome_58   ClientHelloID = ClientHelloID{helloChrome, 58}
	HelloChrome_62   ClientHelloID = ClientHelloID{helloChrome, 62}

	HelloAndroid_Auto        ClientHelloID = ClientHelloID{helloAndroid, helloAutoVers}
	HelloAndroid_6_0_Browser ClientHelloID = ClientHelloID{helloAndroid, 23}
	HelloAndroid_5_1_Browser ClientHelloID = ClientHelloID{helloAndroid, 22}
)

// utlsMacSHA384 returns a SHA-384.
func utlsMacSHA384(version uint16, key []byte) macFunction {
	return tls10MAC{hmac.New(sha512.New384, key)}
}

var utlsSupportedSignatureAlgorithms []signatureAndHash
var utlsSupportedCipherSuites []*cipherSuite

func init() {
	utlsSupportedSignatureAlgorithms = append(supportedSignatureAlgorithms,
		[]signatureAndHash{{disabledHashSHA512, signatureRSA}, {disabledHashSHA512, signatureECDSA}}...)
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
		{OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, 32, 0, 12, ecdheECDSAKA,
			suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff, nil, nil, aeadChaCha20Poly1305},
	}...)
}

// EnableWeakCiphers allows utls connections to continue in some cases, when weak cipher was chosen.
// This provides better compatibility with servers on the web, but weakens security. Feel free
// to use this option if you establish additional secure connection inside of utls connection.
// This option does not change the shape of parrots (i.e. same ciphers will be offered either way).
func EnableWeakCiphers() {
	utlsSupportedCipherSuites = append(cipherSuites, []*cipherSuite{
		{DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256, 32, 32, 16, rsaKA,
			suiteTLS12 | suiteDefaultOff, cipherAES, macSHA256, nil},

		{DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheECDSAKA,
			suiteECDHE | suiteECDSA | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
		{DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, 32, 48, 16, ecdheRSAKA,
			suiteECDHE | suiteTLS12 | suiteDefaultOff | suiteSHA384, cipherAES, utlsMacSHA384, nil},
	}...)
}

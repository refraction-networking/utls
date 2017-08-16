// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"sort"
	"strconv"
	"time"
)

func (uconn *UConn) generateClientHelloConfig(id ClientHelloID) error {
	uconn.clientHelloID = id
	switch uconn.clientHelloID {
	case HelloFirefox_55:
		return uconn.parrotFirefox_55()

	case HelloAndroid_6_0_Browser:
		return uconn.parrotAndroid_6_0()
	case HelloAndroid_5_1_Browser:
		return uconn.parrotAndroid_5_1()

	case HelloChrome_58:
		return uconn.parrotChrome_58()

	case HelloRandomizedALPN:
		return uconn.parrotRandomizedALPN()
	case HelloRandomizedNoALPN:
		return uconn.parrotRandomizedNoALPN()

	case HelloCustom:
		return uconn.parrotCustom()

	// following ClientHello's are aliases, so we call generateClientHelloConfig() again to set the correct id
	case HelloRandomized:
		if tossBiasedCoin(0.5) {
			return uconn.generateClientHelloConfig(HelloRandomizedALPN)
		} else {
			return uconn.generateClientHelloConfig(HelloRandomizedNoALPN)
		}
	case HelloAndroid_Auto:
		return uconn.generateClientHelloConfig(HelloAndroid_6_0_Browser)
	case HelloFirefox_Auto:
		return uconn.generateClientHelloConfig(HelloFirefox_55)
	case HelloChrome_Auto:
		return uconn.generateClientHelloConfig(HelloChrome_58)

	default:
		return errors.New("Unknown ParrotID: " + id.Str())
	}
	return nil
}

// Fills clientHello header(everything but extensions) fields, which are not set explicitly yet, with defaults
func (uconn *UConn) fillClientHelloHeader() error {
	hello := uconn.HandshakeState.Hello
	if hello.Vers == 0 {
		hello.Vers = VersionTLS12
	}
	switch len(hello.Random) {
	case 0:
		hello.Random = make([]byte, 32)
		_, err := io.ReadFull(uconn.config.rand(), hello.Random)
		if err != nil {
			return errors.New("tls: short read from Rand: " + err.Error())
		}
	case 32:
		// carry on
	default:
		return errors.New("ClientHello expected length: 32 bytes. Got: " +
			strconv.Itoa(len(hello.Random)) + " bytes")
	}
	if len(hello.CipherSuites) == 0 {
		hello.CipherSuites = defaultCipherSuites()
	}
	if len(hello.CompressionMethods) == 0 {
		hello.CompressionMethods = []uint8{compressionNone}
	}
	return nil
}

func (uconn *UConn) parrotFirefox_55() error {
	hello := uconn.HandshakeState.Hello
	session := uconn.HandshakeState.Session
	hello.CipherSuites = []uint16{
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}
	err := uconn.fillClientHelloHeader()
	if err != nil {
		return err
	}

	sni := SNIExtension{uconn.config.ServerName}
	ems := utlsExtendedMasterSecretExtension{}
	reneg := RenegotiationInfoExtension{renegotiation: RenegotiateOnceAsClient}
	curves := SupportedCurvesExtension{[]CurveID{X25519, CurveP256, CurveP384, CurveP521}}
	points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
	sessionTicket := SessionTicketExtension{Session: session}
	if session != nil {
		sessionTicket.Session = session
		if len(session.SessionTicket()) > 0 {
			hello.SessionId = make([]byte, 32)
			_, err := io.ReadFull(uconn.config.rand(), hello.SessionId)
			if err != nil {
				return errors.New("tls: short read from Rand: " + err.Error())
			}
		}
	}
	alpn := ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
	status := StatusRequestExtension{}
	sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
		{hashSHA256, signatureECDSA},
		{hashSHA384, signatureECDSA},
		{disabledHashSHA512, signatureECDSA},
		fakeRsaPssSha256,
		fakeRsaPssSha384,
		fakeRsaPssSha512,
		{hashSHA256, signatureRSA},
		{hashSHA384, signatureRSA},
		{disabledHashSHA512, signatureRSA},
		{hashSHA1, signatureECDSA},
		{hashSHA1, signatureRSA}},
	}
	padding := utlsPaddingExtension{GetPaddingLen: boringPaddingStyle}
	uconn.Extensions = []TLSExtension{
		&sni,
		&ems,
		&reneg,
		&curves,
		&points,
		&sessionTicket,
		&alpn,
		&status,
		&sigAndHash,
		&padding,
	}
	return nil
}

func (uconn *UConn) parrotAndroid_6_0() error {
	hello := uconn.HandshakeState.Hello
	session := uconn.HandshakeState.Session

	hello.CipherSuites = []uint16{
		OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
	}
	err := uconn.fillClientHelloHeader()
	if err != nil {
		return err
	}

	sni := SNIExtension{uconn.config.ServerName}
	ems := utlsExtendedMasterSecretExtension{}
	sessionTicket := SessionTicketExtension{Session: session}
	if session != nil {
		sessionTicket.Session = session
		if len(session.SessionTicket()) > 0 {
			sessionId := sha256.Sum256(session.SessionTicket())
			hello.SessionId = sessionId[:]
		}
	}
	sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
		{disabledHashSHA512, signatureRSA},
		{disabledHashSHA512, signatureECDSA},
		{hashSHA384, signatureRSA},
		{hashSHA384, signatureECDSA},
		{hashSHA256, signatureRSA},
		{hashSHA256, signatureECDSA},
		{fakeHashSHA224, signatureRSA},
		{fakeHashSHA224, signatureECDSA},
		{hashSHA1, signatureRSA},
		{hashSHA1, signatureECDSA}},
	}
	status := StatusRequestExtension{}
	npn := NPNExtension{}
	sct := SCTExtension{}
	alpn := ALPNExtension{AlpnProtocols: []string{"http/1.1", "spdy/8.1"}}
	points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
	curves := SupportedCurvesExtension{[]CurveID{CurveP256, CurveP384}}
	padding := utlsPaddingExtension{GetPaddingLen: boringPaddingStyle}

	uconn.Extensions = []TLSExtension{
		&sni,
		&ems,
		&sessionTicket,
		&sigAndHash,
		&status,
		&npn,
		&sct,
		&alpn,
		&points,
		&curves,
		&padding,
	}
	return nil
}
func (uconn *UConn) parrotAndroid_5_1() error {
	hello := uconn.HandshakeState.Hello
	session := uconn.HandshakeState.Session

	hello.CipherSuites = []uint16{
		OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_RC4_128_SHA,
		FAKE_TLS_RSA_WITH_RC4_128_MD5,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
	}
	err := uconn.fillClientHelloHeader()
	if err != nil {
		return err
	}

	sni := SNIExtension{uconn.config.ServerName}
	sessionTicket := SessionTicketExtension{Session: session}
	if session != nil {
		sessionTicket.Session = session
		if len(session.SessionTicket()) > 0 {
			sessionId := sha256.Sum256(session.SessionTicket())
			hello.SessionId = sessionId[:]
		}
	}
	sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
		{disabledHashSHA512, signatureRSA},
		{disabledHashSHA512, signatureECDSA},
		{hashSHA384, signatureRSA},
		{hashSHA384, signatureECDSA},
		{hashSHA256, signatureRSA},
		{hashSHA256, signatureECDSA},
		{fakeHashSHA224, signatureRSA},
		{fakeHashSHA224, signatureECDSA},
		{hashSHA1, signatureRSA},
		{hashSHA1, signatureECDSA}},
	}
	status := StatusRequestExtension{}
	npn := NPNExtension{}
	sct := SCTExtension{}
	alpn := ALPNExtension{AlpnProtocols: []string{"http/1.1", "spdy/3", "spdy/3.1"}}
	points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
	curves := SupportedCurvesExtension{[]CurveID{CurveP256, CurveP384, CurveP521}}
	padding := utlsPaddingExtension{GetPaddingLen: boringPaddingStyle}

	uconn.Extensions = []TLSExtension{
		&sni,
		&sessionTicket,
		&sigAndHash,
		&status,
		&npn,
		&sct,
		&alpn,
		&points,
		&curves,
		&padding,
	}
	return nil
}

func (uconn *UConn) parrotChrome_58() error {
	hello := uconn.HandshakeState.Hello
	session := uconn.HandshakeState.Session

	err := uconn.fillClientHelloHeader()
	if err != nil {
		return err
	}

	hello.CipherSuites = []uint16{
		GetBoringGREASEValue(hello.Random, ssl_grease_cipher),
		TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_AES_128_GCM_SHA256,
		TLS_RSA_WITH_AES_256_GCM_SHA384,
		TLS_RSA_WITH_AES_128_CBC_SHA,
		TLS_RSA_WITH_AES_256_CBC_SHA,
		TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	}

	grease_ext1 := GetBoringGREASEValue(hello.Random, ssl_grease_extension1)
	grease_ext2 := GetBoringGREASEValue(hello.Random, ssl_grease_extension2)
	if grease_ext1 == grease_ext2 {
		grease_ext2 ^= 0x1010
	}

	grease1 := FakeGREASEExtension{Value: grease_ext1}
	reneg := RenegotiationInfoExtension{renegotiation: RenegotiateOnceAsClient}
	sni := SNIExtension{uconn.config.ServerName}
	ems := utlsExtendedMasterSecretExtension{}
	sessionTicket := SessionTicketExtension{Session: session}
	if session != nil {
		sessionTicket.Session = session
		if len(session.SessionTicket()) > 0 {
			sessionId := sha256.Sum256(session.SessionTicket())
			hello.SessionId = sessionId[:]
		}
	}
	sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: []SignatureAndHash{
		{hashSHA256, signatureECDSA},
		fakeRsaPssSha256,
		{hashSHA256, signatureRSA},
		{hashSHA384, signatureECDSA},
		fakeRsaPssSha384,
		{hashSHA384, signatureRSA},
		fakeRsaPssSha512,
		{disabledHashSHA512, signatureRSA},
		{hashSHA1, signatureRSA}},
	}
	status := StatusRequestExtension{}
	sct := SCTExtension{}
	alpn := ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}}
	channelId := FakeChannelIDExtension{}
	points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}
	curves := SupportedCurvesExtension{[]CurveID{CurveID(GetBoringGREASEValue(hello.Random, ssl_grease_group)),
		X25519, CurveP256, CurveP384}}
	grease2 := FakeGREASEExtension{Value: grease_ext2, Body: []byte{0}}
	padding := utlsPaddingExtension{GetPaddingLen: boringPaddingStyle}

	uconn.Extensions = []TLSExtension{
		&grease1,
		&reneg,
		&sni,
		&ems,
		&sessionTicket,
		&sigAndHash,
		&status,
		&sct,
		&alpn,
		&channelId,
		&points,
		&curves,
		&grease2,
		&padding,
	}
	return nil
}

func (uconn *UConn) parrotRandomizedALPN() error {
	err := uconn.parrotRandomizedNoALPN()
	if len(uconn.config.NextProtos) == 0 {
		// if user didn't specify alpn, choose something popular
		uconn.config.NextProtos = []string{"h2", "http/1.1"}
	}
	alpn := ALPNExtension{AlpnProtocols: uconn.config.NextProtos}
	uconn.Extensions = append(uconn.Extensions, &alpn)
	return err
}

func (uconn *UConn) parrotRandomizedNoALPN() error {
	hello := uconn.HandshakeState.Hello
	session := uconn.HandshakeState.Session

	hello.CipherSuites = make([]uint16, len(defaultCipherSuites()))
	copy(hello.CipherSuites, defaultCipherSuites())
	hello.CipherSuites = removeRandomCiphers(hello.CipherSuites, 0.4)
	err := shuffleCiphers(hello.CipherSuites)
	if err != nil {
		return err
	}
	err = uconn.fillClientHelloHeader()
	if err != nil {
		return err
	}

	sni := SNIExtension{uconn.config.ServerName}
	sessionTicket := SessionTicketExtension{Session: session}
	if session != nil {
		sessionTicket.Session = session
		if len(session.SessionTicket()) > 0 {
			sessionId := sha256.Sum256(session.SessionTicket())
			hello.SessionId = sessionId[:]
		}
	}
	sigAndHashAlgos := []SignatureAndHash{
		{hashSHA256, signatureECDSA},
		{hashSHA256, signatureRSA},
		{hashSHA384, signatureECDSA},
		{hashSHA384, signatureRSA},
		{hashSHA1, signatureRSA},
	}
	if tossBiasedCoin(0.5) {
		sigAndHashAlgos = append(sigAndHashAlgos, SignatureAndHash{disabledHashSHA512, signatureECDSA})
	}
	if tossBiasedCoin(0.5) {
		sigAndHashAlgos = append(sigAndHashAlgos, SignatureAndHash{disabledHashSHA512, signatureRSA})
	}
	if tossBiasedCoin(0.5) {
		sigAndHashAlgos = append(sigAndHashAlgos, SignatureAndHash{hashSHA1, signatureECDSA})
	}
	err = shuffleSignatures(sigAndHashAlgos)
	if err != nil {
		return err
	}
	sigAndHash := SignatureAlgorithmsExtension{SignatureAndHashes: sigAndHashAlgos}

	status := StatusRequestExtension{}
	sct := SCTExtension{}
	points := SupportedPointsExtension{SupportedPoints: []byte{pointFormatUncompressed}}

	curveIDs := []CurveID{}
	if tossBiasedCoin(0.7) {
		curveIDs = append(curveIDs, X25519)
	}
	curveIDs = append(curveIDs, CurveP256, CurveP384)
	if tossBiasedCoin(0.3) {
		curveIDs = append(curveIDs, CurveP521)
	}
	curves := SupportedCurvesExtension{curveIDs}

	padding := utlsPaddingExtension{GetPaddingLen: boringPaddingStyle}
	reneg := RenegotiationInfoExtension{renegotiation: RenegotiateOnceAsClient}

	uconn.Extensions = []TLSExtension{
		&sni,
		&sessionTicket,
		&sigAndHash,
		&points,
		&curves,
	}

	if tossBiasedCoin(0.66) {
		uconn.Extensions = append(uconn.Extensions, &padding)
	}
	if tossBiasedCoin(0.66) {
		uconn.Extensions = append(uconn.Extensions, &status)
	}
	if tossBiasedCoin(0.55) {
		uconn.Extensions = append(uconn.Extensions, &sct)
	}
	if tossBiasedCoin(0.44) {
		uconn.Extensions = append(uconn.Extensions, &reneg)
	}
	err = shuffleTLSExtensions(uconn.Extensions)
	if err != nil {
		return err
	}
	return nil
}

func (uconn *UConn) parrotCustom() error {
	return uconn.fillClientHelloHeader()
}

func tossBiasedCoin(probability float32) bool {
	// probability is expected to be in [0,1]
	// this function never returns errors for ease of use
	const precision = 0xffff
	threshold := float32(precision) * probability
	value, err := getRandInt(precision)
	if err != nil {
		// I doubt that this code will ever actually be used, as other functions are expected to complain
		// about used source of entropy. Nonetheless, this is more than enough for given purpose
		return ((time.Now().Unix() & 1) == 0)
	}

	if float32(value) <= threshold {
		return true
	} else {
		return false
	}
}

func removeRandomCiphers(s []uint16, maxRemovalProbability float32) []uint16 {
	// removes elements in place
	// probability to remove increases for further elements
	// never remove first cipher
	if len(s) <= 1 {
		return s
	}

	// remove random elements
	floatLen := float32(len(s))
	sliceLen := len(s)
	for i := 1; i < sliceLen; i++ {
		if tossBiasedCoin(maxRemovalProbability * float32(i) / floatLen) {
			s = append(s[:i], s[i+1:]...)
			sliceLen--
			i--
		}
	}
	return s
}

func getRandInt(max int) (int, error) {
	bigInt, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(bigInt.Int64()), err
}

func getRandPerm(n int) ([]int, error) {
	permArray := make([]int, n)
	for i := 1; i < n; i++ {
		j, err := getRandInt(i + 1)
		if err != nil {
			return permArray, err
		}
		permArray[i] = permArray[j]
		permArray[j] = i
	}
	return permArray, nil
}

func shuffleCiphers(s []uint16) error {
	// shuffles array in place
	ciphers := make(sortableCiphers, len(cipherSuites))
	perm, err := getRandPerm(len(cipherSuites))
	if err != nil {
		return err
	}
	for i, suite := range cipherSuites {
		ciphers[i] = sortableCipher{suite: suite.id,
			isObsolete: ((suite.flags & suiteTLS12) == 0),
			randomTag:  perm[i]}
	}
	sort.Sort(ciphers)
	s = ciphers.GetCiphers()
	return nil
}

type sortableCipher struct {
	isObsolete bool
	randomTag  int
	suite      uint16
}

type sortableCiphers []sortableCipher

func (ciphers sortableCiphers) Len() int {
	return len(ciphers)
}

func (ciphers sortableCiphers) Less(i, j int) bool {
	if ciphers[i].isObsolete && !ciphers[j].isObsolete {
		return false
	}
	if ciphers[j].isObsolete && !ciphers[i].isObsolete {
		return true
	}
	return ciphers[i].randomTag < ciphers[j].randomTag
}

func (ciphers sortableCiphers) Swap(i, j int) {
	ciphers[i], ciphers[j] = ciphers[j], ciphers[i]
}

func (ciphers sortableCiphers) GetCiphers() []uint16 {
	cipherIDs := make([]uint16, len(ciphers))
	for i := range ciphers {
		cipherIDs[i] = ciphers[i].suite
	}
	return cipherIDs
}

// so much for generics
func shuffleTLSExtensions(s []TLSExtension) error {
	// shuffles array in place
	perm, err := getRandPerm(len(s))
	if err != nil {
		return err
	}
	for i := range s {
		s[i], s[perm[i]] = s[perm[i]], s[i]
	}
	return nil
}

// so much for generics
func shuffleSignatures(s []SignatureAndHash) error {
	// shuffles array in place
	perm, err := getRandPerm(len(s))
	if err != nil {
		return err
	}
	for i := range s {
		s[i], s[perm[i]] = s[perm[i]], s[i]
	}
	return nil
}

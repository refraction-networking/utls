// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// Fingerprinter is a struct largely for holding options for the FingerprintClientHello func
type Fingerprinter struct {
	// AllowBluntMimicry will ensure that unknown extensions are
	// passed along into the resulting ClientHelloSpec as-is
	// It will not ensure that the PSK is passed along, if you require that, use KeepPSK
	// WARNING: there could be numerous subtle issues with ClientHelloSpecs
	// that are generated with this flag which could compromise security and/or mimicry
	AllowBluntMimicry bool
	// AlwaysAddPadding will always add a UtlsPaddingExtension with BoringPaddingStyle
	// at the end of the extensions list if it isn't found in the fingerprinted hello.
	// This could be useful in scenarios where the hello you are fingerprinting does not
	// have any padding, but you suspect that other changes you make to the final hello
	// (including things like different SNI lengths) would cause padding to be necessary
	AlwaysAddPadding bool
}

// FingerprintClientHello returns a ClientHelloSpec which is based on the
// ClientHello that is passed in as the data argument
//
// If the ClientHello passed in has extensions that are not recognized or cannot be handled
// it will return a non-nil error and a nil *ClientHelloSpec value
//
// The data should be the full tls record, including the record type/version/length header
// as well as the handshake type/length/version header
// https://tools.ietf.org/html/rfc5246#section-6.2
// https://tools.ietf.org/html/rfc5246#section-7.4
func (f *Fingerprinter) FingerprintClientHello(data []byte) (clientHelloSpec *ClientHelloSpec, err error) {
	clientHelloSpec = &ClientHelloSpec{}
	s := cryptobyte.String(data)

	var contentType uint8
	var recordVersion uint16
	if !s.ReadUint8(&contentType) || // record type
		!s.ReadUint16(&recordVersion) || !s.Skip(2) { // record version and length
		return nil, errors.New("unable to read record type, version, and length")
	}

	if recordType(contentType) != recordTypeHandshake {
		return nil, errors.New("record is not a handshake")
	}

	var handshakeVersion uint16
	var handshakeType uint8

	if !s.ReadUint8(&handshakeType) || !s.Skip(3) || // message type and 3 byte length
		!s.ReadUint16(&handshakeVersion) || !s.Skip(32) { // 32 byte random
		return nil, errors.New("unable to read handshake message type, length, and random")
	}

	if handshakeType != typeClientHello {
		return nil, errors.New("handshake message is not a ClientHello")
	}

	clientHelloSpec.TLSVersMin = recordVersion
	clientHelloSpec.TLSVersMax = handshakeVersion

	var ignoredSessionID cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&ignoredSessionID) {
		return nil, errors.New("unable to read session id")
	}

	// CipherSuites
	var cipherSuitesBytes cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuitesBytes) {
		return nil, errors.New("unable to read ciphersuites")
	}
	err = clientHelloSpec.ReadCipherSuites(cipherSuitesBytes)
	if err != nil {
		return nil, err
	}

	// CompressionMethods
	var compressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil, errors.New("unable to read compression methods")
	}
	err = clientHelloSpec.ReadCompressionMethods(compressionMethods)
	if err != nil {
		return nil, err
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return clientHelloSpec, nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) {
		return nil, errors.New("unable to read extensions data")
	}

	err = clientHelloSpec.ReadTLSExtensions(extensions, f.AllowBluntMimicry)
	if err != nil {
		return nil, err
	}

	if f.AlwaysAddPadding {
		clientHelloSpec.AlwaysAddPadding()
	}

	return clientHelloSpec, nil
}

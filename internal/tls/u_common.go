// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file and the other u_*.go files in this package are uTLS-owned: they
// are never touched by upstream/sync.sh. They add ClientHello fingerprinting
// on top of the mirrored crypto/tls, driven by the public API in the module's
// root package.
//
// Design: the public (root-package) API builds a ClientHelloSpec, attaches it
// to a *Conn through a UConn, and runs the normal crypto/tls client handshake.
// A small set of [uTLS]-marked hooks in the upstream-owned files hand control
// to this code at four points: rendering the ClientHello, re-rendering it on a
// HelloRetryRequest, letting the caller mutate the final bytes (and recomputing
// PSK binders), and letting the caller verify the server with handshake state
// in hand. Everything else is stock crypto/tls.

package tls

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
)

// GREASEPlaceholder is a sentinel CurveID / cipher / version / extension value.
// When the renderer meets it, it substitutes a real GREASE value (RFC 8701).
const GREASEPlaceholder = 0x0a0a

// A few TLS 1.3-era extension code points that upstream crypto/tls does not
// name because it does not implement them, but that fingerprints need.
// These are not declared by the mirrored common.go because upstream crypto/tls
// does not implement them. (extensionECHOuterExtensions and a handful of others
// are already declared there; do not redeclare those here.)
const (
	extensionPadding                uint16 = 21    // RFC 7685
	extensionCompressCertificate    uint16 = 27    // RFC 8879
	extensionRecordSizeLimit        uint16 = 28    // RFC 8449
	extensionDelegatedCredentials   uint16 = 34    // RFC 9345
	extensionNextProtoNeg           uint16 = 13172 // NPN, not IANA assigned
	extensionApplicationSettings    uint16 = 17513 // ALPS, old codepoint
	extensionApplicationSettingsNew uint16 = 17613 // ALPS, new codepoint
	fakeExtensionTokenBinding       uint16 = 24
	fakeExtensionChannelID          uint16 = 30032
	fakeOldExtensionChannelID       uint16 = 30031
)

// isGREASEUint16 reports whether v is one of the sixteen GREASE values.
func isGREASEUint16(v uint16) bool {
	// GREASE values are 0x0a0a, 0x1a1a, ..., 0xfafa: low byte == high byte and
	// low nibble of the high byte is 0x0a.
	return v&0x0f0f == 0x0a0a && v&0xff == v>>8
}

// unGREASEUint16 maps a real value through unchanged, and a GREASE value to the
// placeholder, so fingerprints captured from the wire round-trip.
func unGREASEUint16(v uint16) uint16 {
	if isGREASEUint16(v) {
		return GREASEPlaceholder
	}
	return v
}

// CertCompressionAlgo identifies a certificate compression algorithm (RFC 8879).
type CertCompressionAlgo uint16

const (
	CertCompressionZlib   CertCompressionAlgo = 1
	CertCompressionBrotli CertCompressionAlgo = 2
	CertCompressionZstd   CertCompressionAlgo = 3
)

// keyShareKeyPriv holds the private half of one offered key share, so that if
// the server selects a group other than the primary one, the handshake can
// still complete. Upstream's keySharePrivateKeys holds only a single ECDHE key
// plus an optional ML-KEM key; a fingerprint may offer several key shares.
type keyShareKeyPriv struct {
	ecdhe *ecdh.PrivateKey
	// mlkem is set only for the hybrid group that carries one.
	hybrid *keySharePrivateKeys
}

var (
	errNoSpec          = errors.New("utls: no ClientHelloSpec set on connection")
	errHelloAlreadySet = errors.New("utls: ClientHello already built")
)

// put16 and put24 are small helpers used by the renderer.
func put16(b []byte, v uint16) { binary.BigEndian.PutUint16(b, v) }

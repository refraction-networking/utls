// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file and the other u_*.go files in this package are uTLS-owned: they
// are never touched by upstream/sync.sh. They add ClientHello fingerprinting
// on top of the mirrored crypto/tls, driven by the public API in the module's
// root package.
//
// ClientHello lifecycle (see docs/ARCHITECTURE.md):
//
//  1. build   (makeClientHello hunk -> UConn.prepareHello): the spec and the
//     Config produce the LOGICAL ClientHello (versions, suites, groups, key
//     shares, ALPN, SNI, ...) and a per-connection renderer is attached.
//  2. session (clientHandshake hunk -> Conn.uLoadSession): a cached or injected
//     session adds a ticket / PSK identity; binders are computed over the
//     rendered bytes; the ClientHello hook may rewrite Random/SessionID, after
//     which binders are recomputed and nothing else may have changed.
//  3. render  (clientHelloMsg.marshal hunk): EVERY serialization (transcript,
//     wire, binder input, ECH outer AAD, EncodedClientHelloInner, the retried
//     hello after HelloRetryRequest) is rendered from the current logical
//     message in the spec's order. There is no frozen copy of the bytes.
//  4. negotiate: CompressedCertificate, ALPS and record_size_limit are handled
//     by small hunks in the TLS 1.3 client.
package tls

import (
	"errors"
)

// GREASEPlaceholder is a sentinel CurveID / cipher / version / signature
// scheme value. The renderer substitutes a per-connection GREASE value.
const GREASEPlaceholder = 0x0a0a

// Extension code points crypto/tls does not name because it does not use them.
const (
	extensionPadding                uint16 = 21    // RFC 7685
	extensionCompressCertificate    uint16 = 27    // RFC 8879
	extensionRecordSizeLimit        uint16 = 28    // RFC 8449
	extensionDelegatedCredentials   uint16 = 34    // RFC 9345
	extensionApplicationSettings    uint16 = 17513 // ALPS, old codepoint
	extensionApplicationSettingsNew uint16 = 17613 // ALPS, new codepoint
	extensionTrustAnchors           uint16 = 0xca34
)

// typeCompressedCertificate is the RFC 8879 handshake message type.
const typeCompressedCertificate uint8 = 25

// isGREASEUint16 reports whether v is one of the sixteen GREASE values.
func isGREASEUint16(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v&0xff == v>>8
}

// CertCompressionAlgo identifies a certificate compression algorithm (RFC 8879).
type CertCompressionAlgo uint16

const (
	CertCompressionZlib   CertCompressionAlgo = 1
	CertCompressionBrotli CertCompressionAlgo = 2
	CertCompressionZstd   CertCompressionAlgo = 3
)

func (a CertCompressionAlgo) supported() bool {
	return a == CertCompressionZlib || a == CertCompressionBrotli || a == CertCompressionZstd
}

var (
	// ErrNoSpec is returned by a handshake whose fingerprint has no
	// ClientHelloSpec (HelloCustom without ApplyPreset, or a zero ClientHelloID).
	// uTLS never falls back to the stock crypto/tls ClientHello implicitly.
	ErrNoSpec = errors.New("utls: no ClientHelloSpec: call ApplyPreset (HelloCustom) or use HelloGolang explicitly")
	// ErrHookWithECH is returned when a ClientHello hook is combined with ECH:
	// the hook would see ClientHelloInner bytes that never go on the wire.
	ErrHookWithECH = errors.New("utls: a ClientHello hook cannot be combined with Encrypted Client Hello")
)

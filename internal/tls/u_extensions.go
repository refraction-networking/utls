// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/cryptobyte"
)

// TLSExtension is a single ClientHello extension that the renderer can both
// serialize and account for in the logical handshake state.
//
// Downstream never implements this interface directly; the root package offers
// concrete types and a GenericExtension escape hatch. Keeping it unexported at
// the method level (writeToHello) means the extension set can gain fields
// without breaking downstream, which is a core goal of the v2 redesign.
type TLSExtension interface {
	// ID returns the extension's IANA code point (a GREASE extension reports
	// its drawn value). Downstream fingerprint tooling needs this accessor;
	// upstream uTLS never had one.
	ID() uint16
	// marshal returns the full extension bytes: 2-byte type, 2-byte length,
	// then body. r supplies GREASE values and generated key material.
	marshal(r *helloRenderer) ([]byte, error)
	// writeToHello records the extension's effect on the logical ClientHello
	// so crypto/tls's state machine stays consistent with the wire bytes.
	writeToHello(r *helloRenderer) error
}

// extHeader prepends the 2-byte type and 2-byte length to a body.
func extHeader(id uint16, body []byte) []byte {
	out := make([]byte, 4+len(body))
	put16(out[0:], id)
	put16(out[2:], uint16(len(body)))
	copy(out[4:], body)
	return out
}

// --- SNI -------------------------------------------------------------------

// SNIExtension is server_name (RFC 6066). An empty ServerName takes the value
// from the connection's configured ServerName at render time; a literal IP is
// omitted entirely, matching browser behaviour.
type SNIExtension struct {
	ServerName string
}

func (e *SNIExtension) ID() uint16 { return extensionServerName }

func (e *SNIExtension) writeToHello(r *helloRenderer) error {
	if e.ServerName != "" {
		r.hello.serverName = hostnameInSNI(e.ServerName)
	}
	return nil
}

func (e *SNIExtension) marshal(r *helloRenderer) ([]byte, error) {
	name := e.ServerName
	if name == "" {
		name = r.hello.serverName
	}
	host := hostnameInSNI(name)
	if host == "" {
		// IP address or empty: send an empty server_name_list, like crypto/tls.
		return extHeader(e.ID(), nil), nil
	}
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // host_name
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddBytes([]byte(host))
		})
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- supported_versions ----------------------------------------------------

// SupportedVersionsExtension lists the TLS versions offered (RFC 8446).
type SupportedVersionsExtension struct {
	Versions []uint16
}

func (e *SupportedVersionsExtension) ID() uint16 { return extensionSupportedVersions }

func (e *SupportedVersionsExtension) writeToHello(r *helloRenderer) error {
	vers := make([]uint16, 0, len(e.Versions))
	for _, v := range e.Versions {
		if isGREASEUint16(v) {
			continue
		}
		vers = append(vers, v)
	}
	r.hello.supportedVersions = vers
	return nil
}

func (e *SupportedVersionsExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, v := range e.Versions {
			b.AddUint16(r.grease(v))
		}
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- supported_groups ------------------------------------------------------

// SupportedCurvesExtension lists named groups (RFC 8446 supported_groups).
type SupportedCurvesExtension struct {
	Curves []CurveID
}

func (e *SupportedCurvesExtension) ID() uint16 { return extensionSupportedCurves }

func (e *SupportedCurvesExtension) writeToHello(r *helloRenderer) error {
	curves := make([]CurveID, 0, len(e.Curves))
	for _, c := range e.Curves {
		if isGREASEUint16(uint16(c)) {
			continue
		}
		curves = append(curves, c)
	}
	r.hello.supportedCurves = curves
	return nil
}

func (e *SupportedCurvesExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, c := range e.Curves {
			b.AddUint16(r.grease(uint16(c)))
		}
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- ec_point_formats ------------------------------------------------------

// SupportedPointsExtension is ec_point_formats (RFC 4492).
type SupportedPointsExtension struct {
	SupportedPoints []uint8
}

func (e *SupportedPointsExtension) ID() uint16 { return extensionSupportedPoints }

func (e *SupportedPointsExtension) writeToHello(r *helloRenderer) error {
	r.hello.supportedPoints = e.SupportedPoints
	return nil
}

func (e *SupportedPointsExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(e.SupportedPoints)
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- signature_algorithms --------------------------------------------------

// SignatureAlgorithmsExtension is signature_algorithms (RFC 8446).
type SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsExtension) ID() uint16 { return extensionSignatureAlgorithms }

func (e *SignatureAlgorithmsExtension) writeToHello(r *helloRenderer) error {
	r.hello.supportedSignatureAlgorithms = e.SupportedSignatureAlgorithms
	return nil
}

func (e *SignatureAlgorithmsExtension) marshal(r *helloRenderer) ([]byte, error) {
	return marshalSigAlgs(e.ID(), e.SupportedSignatureAlgorithms, r)
}

// SignatureAlgorithmsCertExtension is signature_algorithms_cert (RFC 8446).
type SignatureAlgorithmsCertExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsCertExtension) ID() uint16 { return extensionSignatureAlgorithmsCert }

func (e *SignatureAlgorithmsCertExtension) writeToHello(r *helloRenderer) error {
	r.hello.supportedSignatureAlgorithmsCert = e.SupportedSignatureAlgorithms
	return nil
}

func (e *SignatureAlgorithmsCertExtension) marshal(r *helloRenderer) ([]byte, error) {
	return marshalSigAlgs(e.ID(), e.SupportedSignatureAlgorithms, r)
}

func marshalSigAlgs(id uint16, algs []SignatureScheme, r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, a := range algs {
			b.AddUint16(r.grease(uint16(a)))
		}
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(id, body), nil
}

// --- ALPN ------------------------------------------------------------------

// ALPNExtension is application_layer_protocol_negotiation (RFC 7301).
type ALPNExtension struct {
	AlpnProtocols []string
}

func (e *ALPNExtension) ID() uint16 { return extensionALPN }

func (e *ALPNExtension) writeToHello(r *helloRenderer) error {
	r.hello.alpnProtocols = e.AlpnProtocols
	return nil
}

func (e *ALPNExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, p := range e.AlpnProtocols {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(p))
			})
		}
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- application_settings (ALPS) -------------------------------------------

// ApplicationSettingsExtension is ALPS. SupportedProtocols lists the ALPN
// protocols for which settings are offered. CodePoint selects the old (17513)
// or new (17613) extension number; it defaults to the old one.
type ApplicationSettingsExtension struct {
	SupportedProtocols []string
	CodePoint          uint16
}

func (e *ApplicationSettingsExtension) ID() uint16 {
	if e.CodePoint != 0 {
		return e.CodePoint
	}
	return extensionApplicationSettings
}

func (e *ApplicationSettingsExtension) writeToHello(r *helloRenderer) error { return nil }

func (e *ApplicationSettingsExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, p := range e.SupportedProtocols {
			b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte(p))
			})
		}
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- status_request, SCT, EMS, renegotiation (fixed bodies) ---------------

// StatusRequestExtension is status_request (OCSP, RFC 6066).
type StatusRequestExtension struct{}

func (e *StatusRequestExtension) ID() uint16 { return extensionStatusRequest }
func (e *StatusRequestExtension) writeToHello(r *helloRenderer) error {
	r.hello.ocspStapling = true
	return nil
}
func (e *StatusRequestExtension) marshal(r *helloRenderer) ([]byte, error) {
	// status_type = ocsp(1), empty responder_id_list, empty request_extensions.
	return extHeader(e.ID(), []byte{0x01, 0x00, 0x00, 0x00, 0x00}), nil
}

// SCTExtension is signed_certificate_timestamp (RFC 6962).
type SCTExtension struct{}

func (e *SCTExtension) ID() uint16                          { return extensionSCT }
func (e *SCTExtension) writeToHello(r *helloRenderer) error { r.hello.scts = true; return nil }
func (e *SCTExtension) marshal(r *helloRenderer) ([]byte, error) {
	return extHeader(e.ID(), nil), nil
}

// ExtendedMasterSecretExtension is extended_master_secret (RFC 7627).
type ExtendedMasterSecretExtension struct{}

func (e *ExtendedMasterSecretExtension) ID() uint16 { return extensionExtendedMasterSecret }
func (e *ExtendedMasterSecretExtension) writeToHello(r *helloRenderer) error {
	r.hello.extendedMasterSecret = true
	return nil
}
func (e *ExtendedMasterSecretExtension) marshal(r *helloRenderer) ([]byte, error) {
	return extHeader(e.ID(), nil), nil
}

// RenegotiationInfoExtension is renegotiation_info (RFC 5746).
type RenegotiationInfoExtension struct{}

func (e *RenegotiationInfoExtension) ID() uint16 { return extensionRenegotiationInfo }
func (e *RenegotiationInfoExtension) writeToHello(r *helloRenderer) error {
	r.hello.secureRenegotiationSupported = true
	return nil
}
func (e *RenegotiationInfoExtension) marshal(r *helloRenderer) ([]byte, error) {
	return extHeader(e.ID(), []byte{0x00}), nil
}

// SessionTicketExtension is session_ticket (RFC 5077). An empty ticket offers
// support without resuming.
type SessionTicketExtension struct{}

func (e *SessionTicketExtension) ID() uint16 { return extensionSessionTicket }
func (e *SessionTicketExtension) writeToHello(r *helloRenderer) error {
	r.hello.ticketSupported = true
	return nil
}
func (e *SessionTicketExtension) marshal(r *helloRenderer) ([]byte, error) {
	return extHeader(e.ID(), nil), nil
}

// --- psk_key_exchange_modes ------------------------------------------------

// PSKKeyExchangeModesExtension is psk_key_exchange_modes (RFC 8446).
type PSKKeyExchangeModesExtension struct {
	Modes []uint8
}

func (e *PSKKeyExchangeModesExtension) ID() uint16 { return extensionPSKModes }
func (e *PSKKeyExchangeModesExtension) writeToHello(r *helloRenderer) error {
	r.hello.pskModes = e.Modes
	return nil
}
func (e *PSKKeyExchangeModesExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.Modes) })
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- compress_certificate --------------------------------------------------

// CompressCertificateExtension is compress_certificate (RFC 8879).
type CompressCertificateExtension struct {
	Algorithms []CertCompressionAlgo
}

func (e *CompressCertificateExtension) ID() uint16                          { return extensionCompressCertificate }
func (e *CompressCertificateExtension) writeToHello(r *helloRenderer) error { return nil }
func (e *CompressCertificateExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, a := range e.Algorithms {
			b.AddUint16(uint16(a))
		}
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// --- record_size_limit -----------------------------------------------------

// RecordSizeLimitExtension is record_size_limit (RFC 8449).
type RecordSizeLimitExtension struct {
	Limit uint16
}

func (e *RecordSizeLimitExtension) ID() uint16                          { return extensionRecordSizeLimit }
func (e *RecordSizeLimitExtension) writeToHello(r *helloRenderer) error { return nil }
func (e *RecordSizeLimitExtension) marshal(r *helloRenderer) ([]byte, error) {
	body := make([]byte, 2)
	put16(body, e.Limit)
	return extHeader(e.ID(), body), nil
}

// --- GREASE ----------------------------------------------------------------

// UtlsGREASEExtension is a GREASE extension (RFC 8701). Value is the drawn
// extension type (filled by the renderer when zero); Body is usually empty but
// is non-empty for the second GREASE extension in a Chrome hello (a single
// 0x00 byte).
type UtlsGREASEExtension struct {
	Value uint16
	Body  []byte
}

func (e *UtlsGREASEExtension) ID() uint16                          { return e.Value }
func (e *UtlsGREASEExtension) writeToHello(r *helloRenderer) error { return nil }
func (e *UtlsGREASEExtension) marshal(r *helloRenderer) ([]byte, error) {
	if e.Value == 0 {
		e.Value = r.nextGREASE()
	}
	return extHeader(e.Value, e.Body), nil
}

// --- padding (RFC 7685) -----------------------------------------------------

// UtlsPaddingExtension pads the ClientHello. If GetPaddingLen is nil the
// BoringSSL heuristic is used: pad so the record body is at least 512 bytes.
type UtlsPaddingExtension struct {
	PaddingLen    int
	WillPad       bool
	GetPaddingLen func(clientHelloUnpaddedLen int) (paddingLen int, willPad bool)
}

func (e *UtlsPaddingExtension) ID() uint16                          { return extensionPadding }
func (e *UtlsPaddingExtension) writeToHello(r *helloRenderer) error { return nil }

// BoringPaddingStyle implements BoringSSL's padding heuristic.
func BoringPaddingStyle(unpaddedLen int) (int, bool) {
	if unpaddedLen > 0xff && unpaddedLen < 0x200 {
		paddingLen := 0x200 - unpaddedLen
		if paddingLen >= 4+1 {
			paddingLen -= 4
		} else {
			paddingLen = 1
		}
		return paddingLen, true
	}
	return 0, false
}

func (e *UtlsPaddingExtension) marshal(r *helloRenderer) ([]byte, error) {
	// Padding length is resolved in a second render pass (see helloRenderer),
	// which sets PaddingLen/WillPad before calling marshal.
	if !e.WillPad {
		return extHeader(e.ID(), nil), nil
	}
	return extHeader(e.ID(), make([]byte, e.PaddingLen)), nil
}

// --- generic / opaque ------------------------------------------------------

// GenericExtension carries an arbitrary extension verbatim. It is the escape
// hatch for extensions uTLS does not model and for fingerprints parsed from
// the wire.
type GenericExtension struct {
	Id   uint16
	Data []byte
}

func (e *GenericExtension) ID() uint16                          { return e.Id }
func (e *GenericExtension) writeToHello(r *helloRenderer) error { return nil }
func (e *GenericExtension) marshal(r *helloRenderer) ([]byte, error) {
	return extHeader(e.Id, e.Data), nil
}

// KeyShareEntry is one offered key share. An empty Data means "generate a fresh
// key for this group at render time".
type KeyShareEntry struct {
	Group CurveID
	Data  []byte
}

// KeyShareExtension is key_share (RFC 8446). Groups with empty Data get fresh
// keys generated by the renderer, whose private halves are retained so the
// handshake can complete whichever group the server selects.
type KeyShareExtension struct {
	KeyShares []KeyShareEntry
}

func (e *KeyShareExtension) ID() uint16 { return extensionKeyShare }

func (e *KeyShareExtension) writeToHello(r *helloRenderer) error {
	return r.buildKeyShares(e)
}

func (e *KeyShareExtension) marshal(r *helloRenderer) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, ks := range r.renderedKeyShares {
			b.AddUint16(uint16(ks.group))
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes(ks.data)
			})
		}
	})
	body, err := b.Bytes()
	if err != nil {
		return nil, err
	}
	return extHeader(e.ID(), body), nil
}

// genericReader lets the parser return extensions whose body it could not
// interpret; it is an alias used by the fingerprinter.
var _ io.Reader = (*nopReader)(nil)

type nopReader struct{}

func (nopReader) Read([]byte) (int, error) { return 0, fmt.Errorf("utls: not readable") }

var errUnsupportedExtension = errors.New("utls: unsupported extension")

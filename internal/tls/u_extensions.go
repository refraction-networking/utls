// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// TLSExtension is one ClientHello extension slot in a ClientHelloSpec.
//
// A spec is DECLARATIVE: it fixes the order and the static content of the
// extensions. Fields that the TLS state machine owns (server name, key shares,
// pre-shared keys, cookie, ECH payload, session ticket, ...) are always rendered
// from the live logical ClientHello, so every ClientHello that crypto/tls
// sends (first flight, after HelloRetryRequest, ECH inner/outer, with resumption
// binders) is serialized from the same state the handshake verifies against.
//
// The methods are unexported on purpose: extension kinds are defined inside
// uTLS (where they can integrate with the handshake); downstream composes the
// provided types and uses GenericExtension for opaque extensions.
type TLSExtension interface {
	// ID returns the extension's code point. GREASE extensions return their
	// fixed Value, or GREASEPlaceholder when the value is drawn per connection.
	ID() uint16
	// apply records the extension's effect on the logical ClientHello.
	apply(b *helloBuild) error
	// render returns the extension body for message m, and whether to emit it.
	render(r *helloRenderer, m *clientHelloMsg, slot int) (body []byte, emit bool, err error)
	// clone returns a deep copy, so specs are never shared between connections.
	clone() TLSExtension
}

func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte{}, b...)
}

func buildBody(f func(b *cryptobyte.Builder)) ([]byte, error) {
	var b cryptobyte.Builder
	f(&b)
	return b.Bytes()
}

// legacyEmit reports whether a TLS1.2-era fingerprint extension (EMS,
// renegotiation_info, ec_point_formats, session_ticket) is emitted for m: when
// logically enabled, or always in an ECH ClientHelloOuter, which keeps the
// browser's shape while the TLS 1.3-only inner hello omits them (as crypto/tls
// does).
func legacyEmit(logical bool, m *clientHelloMsg) bool {
	return logical || isECHOuter(m)
}

func isECHOuter(m *clientHelloMsg) bool { return len(m.encryptedClientHello) > 1 }
func isECHInner(m *clientHelloMsg) bool {
	return len(m.encryptedClientHello) == 1 && m.encryptedClientHello[0] == byte(innerECHExt)
}

// --- server_name -------------------------------------------------------------

// SNIExtension is server_name (RFC 6066). ServerName overrides the name taken
// from Config.ServerName. IP literals and empty names are never sent: the
// extension is omitted entirely, as browsers and crypto/tls do.
type SNIExtension struct {
	ServerName string
}

func (e *SNIExtension) ID() uint16           { return extensionServerName }
func (e *SNIExtension) clone() TLSExtension { c := *e; return &c }
func (e *SNIExtension) apply(b *helloBuild) error {
	b.hasSNI = true
	if e.ServerName != "" {
		b.hello.serverName = hostnameInSNI(e.ServerName)
	}
	return nil
}
func (e *SNIExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if m.serverName == "" {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint8(0) // host_name
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(m.serverName)) })
		})
	})
	return body, true, err
}

// --- supported_versions ------------------------------------------------------

// SupportedVersionsExtension lists offered versions (RFC 8446). Versions outside
// Config.MinVersion/MaxVersion and ClientHelloSpec.TLSVersMin/TLSVersMax are
// removed before rendering; GREASE_PLACEHOLDER entries become GREASE values.
type SupportedVersionsExtension struct {
	Versions []uint16
}

func (e *SupportedVersionsExtension) ID() uint16 { return extensionSupportedVersions }
func (e *SupportedVersionsExtension) clone() TLSExtension {
	return &SupportedVersionsExtension{slices.Clone(e.Versions)}
}
func (e *SupportedVersionsExtension) apply(b *helloBuild) error {
	b.specVersions = e.Versions
	return nil
}
func (e *SupportedVersionsExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if len(m.supportedVersions) == 0 {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, v := range e.Versions {
				if isGREASEUint16(v) {
					b.AddUint16(r.grease.version)
				} else if slices.Contains(m.supportedVersions, v) {
					b.AddUint16(v)
				}
			}
		})
	})
	return body, true, err
}

// --- supported_groups -------------------------------------------------------

// SupportedCurvesExtension lists named groups. When Config.CurvePreferences is
// set, groups not in it are removed (key shares too).
type SupportedCurvesExtension struct {
	Curves []CurveID
}

func (e *SupportedCurvesExtension) ID() uint16 { return extensionSupportedCurves }
func (e *SupportedCurvesExtension) clone() TLSExtension {
	return &SupportedCurvesExtension{slices.Clone(e.Curves)}
}
func (e *SupportedCurvesExtension) apply(b *helloBuild) error {
	b.hello.supportedCurves = nil
	for _, c := range e.Curves {
		if !isGREASEUint16(uint16(c)) && b.groupAllowed(c) {
			b.hello.supportedCurves = append(b.hello.supportedCurves, c)
		}
	}
	return nil
}
func (e *SupportedCurvesExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if len(m.supportedCurves) == 0 {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, c := range e.Curves {
				if isGREASEUint16(uint16(c)) {
					b.AddUint16(r.grease.group)
				} else if slices.Contains(m.supportedCurves, c) {
					b.AddUint16(uint16(c))
				}
			}
		})
	})
	return body, true, err
}

// --- ec_point_formats ----------------------------------------------------------

// SupportedPointsExtension is ec_point_formats (RFC 8422).
type SupportedPointsExtension struct {
	SupportedPoints []uint8
}

func (e *SupportedPointsExtension) ID() uint16 { return extensionSupportedPoints }
func (e *SupportedPointsExtension) clone() TLSExtension {
	return &SupportedPointsExtension{cloneBytes(e.SupportedPoints)}
}
func (e *SupportedPointsExtension) apply(b *helloBuild) error {
	b.hello.supportedPoints = cloneBytes(e.SupportedPoints)
	return nil
}
func (e *SupportedPointsExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if !legacyEmit(len(m.supportedPoints) > 0, m) {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.SupportedPoints) })
	})
	return body, true, err
}

// --- signature_algorithms(_cert) ---------------------------------------------

// SignatureAlgorithmsExtension is signature_algorithms. GREASE_PLACEHOLDER
// entries become a per-connection GREASE value (Chrome 155+).
type SignatureAlgorithmsExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsExtension) ID() uint16 { return extensionSignatureAlgorithms }
func (e *SignatureAlgorithmsExtension) clone() TLSExtension {
	return &SignatureAlgorithmsExtension{slices.Clone(e.SupportedSignatureAlgorithms)}
}
func (e *SignatureAlgorithmsExtension) apply(b *helloBuild) error {
	b.hello.supportedSignatureAlgorithms = ungreaseSchemes(e.SupportedSignatureAlgorithms)
	return nil
}
func (e *SignatureAlgorithmsExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return renderSigAlgs(r, e.SupportedSignatureAlgorithms)
}

// SignatureAlgorithmsCertExtension is signature_algorithms_cert (RFC 8446).
type SignatureAlgorithmsCertExtension struct {
	SupportedSignatureAlgorithms []SignatureScheme
}

func (e *SignatureAlgorithmsCertExtension) ID() uint16 { return extensionSignatureAlgorithmsCert }
func (e *SignatureAlgorithmsCertExtension) clone() TLSExtension {
	return &SignatureAlgorithmsCertExtension{slices.Clone(e.SupportedSignatureAlgorithms)}
}
func (e *SignatureAlgorithmsCertExtension) apply(b *helloBuild) error {
	b.hello.supportedSignatureAlgorithmsCert = ungreaseSchemes(e.SupportedSignatureAlgorithms)
	return nil
}
func (e *SignatureAlgorithmsCertExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return renderSigAlgs(r, e.SupportedSignatureAlgorithms)
}

func ungreaseSchemes(in []SignatureScheme) []SignatureScheme {
	var out []SignatureScheme
	for _, s := range in {
		if !isGREASEUint16(uint16(s)) {
			out = append(out, s)
		}
	}
	return out
}

func renderSigAlgs(r *helloRenderer, algs []SignatureScheme) ([]byte, bool, error) {
	if len(algs) == 0 {
		return nil, false, errors.New("utls: empty signature_algorithms list")
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, a := range algs {
				if isGREASEUint16(uint16(a)) {
					b.AddUint16(r.grease.sigalg)
				} else {
					b.AddUint16(uint16(a))
				}
			}
		})
	})
	return body, true, err
}

// --- ALPN ---------------------------------------------------------------------

// ALPNExtension is application_layer_protocol_negotiation (RFC 7301). If
// Config.NextProtos is set it REPLACES AlpnProtocols (in this slot): the
// application decides which protocols it can speak. Leave NextProtos empty to
// use the fingerprint's list.
type ALPNExtension struct {
	AlpnProtocols []string
}

func (e *ALPNExtension) ID() uint16 { return extensionALPN }
func (e *ALPNExtension) clone() TLSExtension {
	return &ALPNExtension{slices.Clone(e.AlpnProtocols)}
}
func (e *ALPNExtension) apply(b *helloBuild) error {
	b.hasALPN = true
	if len(b.config.NextProtos) == 0 {
		b.hello.alpnProtocols = slices.Clone(e.AlpnProtocols)
	}
	return nil
}
func (e *ALPNExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if len(m.alpnProtocols) == 0 {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, p := range m.alpnProtocols {
				if len(p) == 0 || len(p) > 255 {
					b.SetError(errors.New("utls: invalid ALPN protocol"))
					return
				}
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
			}
		})
	})
	return body, true, err
}

// --- application_settings (ALPS) ---------------------------------------------

// ApplicationSettingsExtension is ALPS (draft-vvv-tls-alps). SupportedProtocols
// lists the ALPN protocols for which the client offers settings; only those
// also offered in ALPN are sent. CodePoint selects 17513 (old, default) or
// 17613 (new, Chrome 131+). Settings is the client's application settings
// payload sent in the client EncryptedExtensions when the server negotiates
// ALPS (for "h2" it defaults to an empty HTTP/2 SETTINGS payload, as Chrome).
type ApplicationSettingsExtension struct {
	SupportedProtocols []string
	CodePoint          uint16
	Settings           []byte
}

func (e *ApplicationSettingsExtension) ID() uint16 {
	if e.CodePoint != 0 {
		return e.CodePoint
	}
	return extensionApplicationSettings
}
func (e *ApplicationSettingsExtension) clone() TLSExtension {
	return &ApplicationSettingsExtension{slices.Clone(e.SupportedProtocols), e.CodePoint, cloneBytes(e.Settings)}
}
func (e *ApplicationSettingsExtension) apply(b *helloBuild) error {
	if id := e.ID(); id != extensionApplicationSettings && id != extensionApplicationSettingsNew {
		return fmt.Errorf("utls: unknown ALPS code point %d", id)
	}
	b.alps = e
	return nil
}
func (e *ApplicationSettingsExtension) protocols(m *clientHelloMsg) []string {
	var out []string
	for _, p := range e.SupportedProtocols {
		if slices.Contains(m.alpnProtocols, p) {
			out = append(out, p)
		}
	}
	return out
}
func (e *ApplicationSettingsExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	ps := e.protocols(m)
	if len(ps) == 0 {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, p := range ps {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte(p)) })
			}
		})
	})
	return body, true, err
}

// --- status_request, SCT, EMS, renegotiation_info, session_ticket ------------

// StatusRequestExtension is status_request (OCSP, RFC 6066).
type StatusRequestExtension struct{}

func (e *StatusRequestExtension) ID() uint16           { return extensionStatusRequest }
func (e *StatusRequestExtension) clone() TLSExtension { return &StatusRequestExtension{} }
func (e *StatusRequestExtension) apply(b *helloBuild) error {
	b.hello.ocspStapling = true
	return nil
}
func (e *StatusRequestExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return []byte{1, 0, 0, 0, 0}, m.ocspStapling, nil
}

// SCTExtension is signed_certificate_timestamp (RFC 6962).
type SCTExtension struct{}

func (e *SCTExtension) ID() uint16                 { return extensionSCT }
func (e *SCTExtension) clone() TLSExtension        { return &SCTExtension{} }
func (e *SCTExtension) apply(b *helloBuild) error { b.hello.scts = true; return nil }
func (e *SCTExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return nil, m.scts, nil
}

// ExtendedMasterSecretExtension is extended_master_secret (RFC 7627).
type ExtendedMasterSecretExtension struct{}

func (e *ExtendedMasterSecretExtension) ID() uint16 { return extensionExtendedMasterSecret }
func (e *ExtendedMasterSecretExtension) clone() TLSExtension {
	return &ExtendedMasterSecretExtension{}
}
func (e *ExtendedMasterSecretExtension) apply(b *helloBuild) error {
	b.hello.extendedMasterSecret = true
	return nil
}
func (e *ExtendedMasterSecretExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return nil, legacyEmit(m.extendedMasterSecret, m), nil
}

// RenegotiationInfoExtension is renegotiation_info (RFC 5746).
type RenegotiationInfoExtension struct{}

func (e *RenegotiationInfoExtension) ID() uint16 { return extensionRenegotiationInfo }
func (e *RenegotiationInfoExtension) clone() TLSExtension {
	return &RenegotiationInfoExtension{}
}
func (e *RenegotiationInfoExtension) apply(b *helloBuild) error {
	b.hello.secureRenegotiationSupported = true
	return nil
}
func (e *RenegotiationInfoExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if !legacyEmit(m.secureRenegotiationSupported, m) {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.secureRenegotiation) })
	})
	return body, true, err
}

// SessionTicketExtension is session_ticket (RFC 5077). The body is the ticket
// of a TLS 1.2 session being resumed (from the session cache or SetSession),
// otherwise empty. It is omitted when Config.SessionTicketsDisabled is set.
type SessionTicketExtension struct{}

func (e *SessionTicketExtension) ID() uint16           { return extensionSessionTicket }
func (e *SessionTicketExtension) clone() TLSExtension { return &SessionTicketExtension{} }
func (e *SessionTicketExtension) apply(b *helloBuild) error {
	b.hasTicket = true
	b.hello.ticketSupported = !b.config.SessionTicketsDisabled
	return nil
}
func (e *SessionTicketExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if r.ticketsDisabled {
		return nil, false, nil
	}
	if isECHOuter(m) {
		return nil, true, nil // never put a resumption ticket in the outer hello
	}
	return cloneBytes(m.sessionTicket), m.ticketSupported, nil
}

// --- psk_key_exchange_modes -----------------------------------------------------

// PSKKeyExchangeModesExtension is psk_key_exchange_modes (RFC 8446). TLS 1.3
// resumption is only offered when the spec contains this extension.
type PSKKeyExchangeModesExtension struct {
	Modes []uint8
}

func (e *PSKKeyExchangeModesExtension) ID() uint16 { return extensionPSKModes }
func (e *PSKKeyExchangeModesExtension) clone() TLSExtension {
	return &PSKKeyExchangeModesExtension{cloneBytes(e.Modes)}
}
func (e *PSKKeyExchangeModesExtension) apply(b *helloBuild) error {
	if len(e.Modes) == 0 {
		return errors.New("utls: empty psk_key_exchange_modes")
	}
	b.pskModes = cloneBytes(e.Modes)
	b.hello.pskModes = cloneBytes(e.Modes)
	return nil
}
func (e *PSKKeyExchangeModesExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(e.Modes) })
	})
	return body, true, err
}

// --- compress_certificate ------------------------------------------------------

// CompressCertificateExtension is compress_certificate (RFC 8879). The client
// accepts CompressedCertificate messages using any listed algorithm; the
// supported algorithms are zlib, brotli and zstd.
type CompressCertificateExtension struct {
	Algorithms []CertCompressionAlgo
}

func (e *CompressCertificateExtension) ID() uint16 { return extensionCompressCertificate }
func (e *CompressCertificateExtension) clone() TLSExtension {
	return &CompressCertificateExtension{slices.Clone(e.Algorithms)}
}
func (e *CompressCertificateExtension) apply(b *helloBuild) error {
	if len(e.Algorithms) == 0 {
		return errors.New("utls: empty compress_certificate algorithm list")
	}
	for _, a := range e.Algorithms {
		if !a.supported() {
			return fmt.Errorf("utls: compress_certificate algorithm %d is not supported", a)
		}
	}
	b.certCompression = slices.Clone(e.Algorithms)
	return nil
}
func (e *CompressCertificateExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, a := range e.Algorithms {
				b.AddUint16(uint16(a))
			}
		})
	})
	return body, true, err
}

// --- record_size_limit ---------------------------------------------------------

// RecordSizeLimitExtension is record_size_limit (RFC 8449). Limit is the largest
// protected record the client will accept (in TLS 1.3 it counts the inner
// content type and padding). It must be in [64, 2^14+1] (2^14 if TLS 1.3 is not
// offered). When the server acknowledges it, incoming protected records over
// the limit are rejected with record_overflow, and the server's own limit is
// applied to outgoing records.
type RecordSizeLimitExtension struct {
	Limit uint16
}

func (e *RecordSizeLimitExtension) ID() uint16 { return extensionRecordSizeLimit }
func (e *RecordSizeLimitExtension) clone() TLSExtension {
	c := *e
	return &c
}
func (e *RecordSizeLimitExtension) apply(b *helloBuild) error {
	if e.Limit < 64 || e.Limit > maxPlaintext+1 {
		return fmt.Errorf("utls: record_size_limit %d outside [64, %d] (RFC 8449)", e.Limit, maxPlaintext+1)
	}
	b.recordSizeLimit = e.Limit
	return nil
}
func (e *RecordSizeLimitExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return []byte{byte(e.Limit >> 8), byte(e.Limit)}, true, nil
}

// --- GREASE --------------------------------------------------------------------

// UtlsGREASEExtension is a GREASE extension (RFC 8701). A zero Value is drawn per
// connection (distinct from the previous GREASE extension, as BoringSSL does).
type UtlsGREASEExtension struct {
	Value uint16
	Body  []byte
}

func (e *UtlsGREASEExtension) ID() uint16 {
	if e.Value == 0 {
		return GREASEPlaceholder
	}
	return e.Value
}
func (e *UtlsGREASEExtension) clone() TLSExtension {
	return &UtlsGREASEExtension{e.Value, cloneBytes(e.Body)}
}
func (e *UtlsGREASEExtension) apply(b *helloBuild) error {
	if e.Value != 0 && !isGREASEUint16(e.Value) {
		return fmt.Errorf("utls: %#04x is not a GREASE value", e.Value)
	}
	return nil
}
func (e *UtlsGREASEExtension) render(r *helloRenderer, m *clientHelloMsg, slot int) ([]byte, bool, error) {
	return cloneBytes(e.Body), true, nil
}

// --- padding -------------------------------------------------------------------

// UtlsPaddingExtension pads the ClientHello (RFC 7685). GetPaddingLen receives
// the length of the complete ClientHello handshake message without this
// extension (including any pre_shared_key) and returns the padding body length.
// nil uses BoringPaddingStyle. Padding is recomputed for every ClientHello.
type UtlsPaddingExtension struct {
	GetPaddingLen func(clientHelloUnpaddedLen int) (paddingLen int, willPad bool)
}

func (e *UtlsPaddingExtension) ID() uint16           { return extensionPadding }
func (e *UtlsPaddingExtension) clone() TLSExtension { c := *e; return &c }
func (e *UtlsPaddingExtension) apply(b *helloBuild) error {
	return nil
}
func (e *UtlsPaddingExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if r.padLen < 0 {
		return nil, false, nil
	}
	return make([]byte, r.padLen), true, nil
}

// BoringPaddingStyle implements BoringSSL's padding heuristic: pad
// ClientHellos of 256..511 bytes to 512.
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

// --- generic -------------------------------------------------------------------

// GenericExtension carries an opaque extension verbatim. It must not carry an
// extension whose meaning the handshake depends on (pre_shared_key,
// early_data, key_share, encrypted_client_hello, cookie, ...): use the typed
// extension instead. Such IDs are rejected.
type GenericExtension struct {
	Id   uint16
	Data []byte
}

func (e *GenericExtension) ID() uint16           { return e.Id }
func (e *GenericExtension) clone() TLSExtension { return &GenericExtension{e.Id, cloneBytes(e.Data)} }
func (e *GenericExtension) apply(b *helloBuild) error {
	switch e.Id {
	case extensionPreSharedKey, extensionEarlyData, extensionKeyShare, extensionEncryptedClientHello,
		extensionCookie, extensionSupportedVersions, extensionServerName, extensionALPN,
		extensionSupportedCurves, extensionSupportedPoints, extensionSignatureAlgorithms,
		extensionSignatureAlgorithmsCert, extensionPSKModes, extensionStatusRequest, extensionSCT,
		extensionExtendedMasterSecret, extensionRenegotiationInfo, extensionQUICTransportParameters,
		extensionECHOuterExtensions, extensionSessionTicket, extensionCompressCertificate,
		extensionRecordSizeLimit, extensionApplicationSettings, extensionApplicationSettingsNew,
		extensionPadding, extensionTrustAnchors:
		return fmt.Errorf("utls: GenericExtension cannot carry extension %d, whose semantics the handshake must implement; use the typed extension", e.Id)
	}
	if isGREASEUint16(e.Id) {
		return errors.New("utls: use UtlsGREASEExtension for GREASE extensions")
	}
	return nil
}
func (e *GenericExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return cloneBytes(e.Data), true, nil
}

// --- key_share -------------------------------------------------------------------

// KeyShareEntry is one offered key share. Empty Data means "generate a fresh key
// for Group" (the private key is retained so the handshake can complete if the
// server picks this group). Group GREASE_PLACEHOLDER emits a GREASE share whose
// group equals the supported_groups GREASE value; Data is its body ({0} if
// empty). Non-GREASE entries with explicit Data are rejected: a share without
// its private key could be selected by the server and fail the handshake.
type KeyShareEntry struct {
	Group CurveID
	Data  []byte
}

// KeyShareExtension is key_share (RFC 8446).
//
// ReuseClassicalFromHybrid makes an X25519 entry that follows an
// X25519MLKEM768 entry reuse the hybrid's X25519 key (Firefox 132+ does this;
// it is also how crypto/tls builds its fallback share).
type KeyShareExtension struct {
	KeyShares                []KeyShareEntry
	ReuseClassicalFromHybrid bool
}

func (e *KeyShareExtension) ID() uint16 { return extensionKeyShare }
func (e *KeyShareExtension) clone() TLSExtension {
	c := &KeyShareExtension{ReuseClassicalFromHybrid: e.ReuseClassicalFromHybrid}
	for _, ks := range e.KeyShares {
		c.KeyShares = append(c.KeyShares, KeyShareEntry{ks.Group, cloneBytes(ks.Data)})
	}
	return c
}
func (e *KeyShareExtension) apply(b *helloBuild) error {
	b.keyShareSpec = e
	return nil // shares are generated by helloBuild.finish once groups are final
}
func (e *KeyShareExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if len(m.keyShares) == 0 {
		return nil, false, nil
	}
	hrr := r.isRetry(m)
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			add := func(g CurveID, data []byte) {
				b.AddUint16(uint16(g))
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(data) })
			}
			if hrr {
				// After HelloRetryRequest the key_share holds exactly the share for
				// the group the server asked for (RFC 8446, Section 4.1.2).
				for _, ks := range m.keyShares {
					add(ks.group, ks.data)
				}
				return
			}
			for _, ks := range e.KeyShares {
				if isGREASEUint16(uint16(ks.Group)) {
					data := ks.Data
					if len(data) == 0 {
						data = []byte{0}
					}
					add(CurveID(r.grease.group), data)
					continue
				}
				for _, l := range m.keyShares {
					if l.group == ks.Group {
						add(l.group, l.data)
						break
					}
				}
			}
		})
	})
	return body, true, err
}

// --- encrypted_client_hello ------------------------------------------------------

// EncryptedClientHelloExtension is the encrypted_client_hello slot. With an ECH
// configuration (Config.EncryptedClientHelloConfigList) it carries the real
// ECH payload in the outer hello and the inner marker in the inner hello.
// Without one, if GREASE is true, it carries a GREASE ECH extension shaped like
// BoringSSL's (random config id, HPKE X25519/HKDF-SHA256/AES-128-GCM, 32-byte
// enc, payload of 144, 176, 208 or 240 bytes), which Chrome always sends.
//
// GREASECipherSuites and GREASEPayloadLengths override the GREASE shape
// (e.g. Firefox: AES-128-GCM or ChaCha20-Poly1305, 239-byte payload).
type EncryptedClientHelloExtension struct {
	GREASE               bool
	GREASECipherSuites   []HPKESymmetricCipherSuite
	GREASEPayloadLengths []uint16
}

// HPKESymmetricCipherSuite is an ECH HPKE KDF/AEAD pair.
type HPKESymmetricCipherSuite struct {
	KDF, AEAD uint16
}

func (e *EncryptedClientHelloExtension) ID() uint16 { return extensionEncryptedClientHello }
func (e *EncryptedClientHelloExtension) clone() TLSExtension {
	return &EncryptedClientHelloExtension{e.GREASE, slices.Clone(e.GREASECipherSuites), slices.Clone(e.GREASEPayloadLengths)}
}
func (e *EncryptedClientHelloExtension) apply(b *helloBuild) error {
	b.hasECHSlot = true
	b.echSlot = e
	for _, l := range e.GREASEPayloadLengths {
		if l < 32 || l > 1024 {
			return fmt.Errorf("utls: GREASE ECH payload length %d out of range", l)
		}
	}
	return nil
}
func (e *EncryptedClientHelloExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if len(m.encryptedClientHello) > 0 {
		return cloneBytes(m.encryptedClientHello), true, nil
	}
	if e.GREASE {
		return cloneBytes(r.echGREASE), true, nil
	}
	return nil, false, nil
}

// --- pre_shared_key / early_data placeholders (from captured hellos) -------------

// PreSharedKeyExtension marks where a fingerprint carries pre_shared_key. The
// extension is rendered from the session actually being resumed (identity,
// obfuscated age and freshly computed binders), and always last as RFC 8446
// requires; it is omitted when no session is resumed. Captured PSK bytes are
// never replayed.
type PreSharedKeyExtension struct{}

func (e *PreSharedKeyExtension) ID() uint16                 { return extensionPreSharedKey }
func (e *PreSharedKeyExtension) clone() TLSExtension        { return &PreSharedKeyExtension{} }
func (e *PreSharedKeyExtension) apply(b *helloBuild) error { return nil }
func (e *PreSharedKeyExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return nil, false, nil // rendered by the renderer at the end
}

// EarlyDataExtension marks early_data. uTLS sends early_data only when the
// handshake actually attempts 0-RTT (QUIC with a resumable session); captured
// early_data indications are never replayed.
type EarlyDataExtension struct{}

func (e *EarlyDataExtension) ID() uint16                 { return extensionEarlyData }
func (e *EarlyDataExtension) clone() TLSExtension        { return &EarlyDataExtension{} }
func (e *EarlyDataExtension) apply(b *helloBuild) error { return nil }
func (e *EarlyDataExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	return nil, m.earlyData, nil
}

// QUICTransportParametersExtension marks the quic_transport_parameters slot. The
// body is supplied by the QUIC implementation through the QUIC API.
type QUICTransportParametersExtension struct{}

func (e *QUICTransportParametersExtension) ID() uint16 { return extensionQUICTransportParameters }
func (e *QUICTransportParametersExtension) clone() TLSExtension {
	return &QUICTransportParametersExtension{}
}
func (e *QUICTransportParametersExtension) apply(b *helloBuild) error {
	b.hasQUICSlot = true
	return nil
}
func (e *QUICTransportParametersExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if m.quicTransportParameters == nil {
		return nil, false, nil
	}
	return cloneBytes(m.quicTransportParameters), true, nil
}

// --- trust_anchors ------------------------------------------------------------------

// TrustAnchorsExtension advertises trust anchor identifiers
// (draft-ietf-tls-trust-anchor-ids), sent by Chrome 155+. It is informational
// for the server's certificate selection; the client does not change behavior.
type TrustAnchorsExtension struct {
	TrustAnchorIDs [][]byte
}

func (e *TrustAnchorsExtension) ID() uint16 { return extensionTrustAnchors }
func (e *TrustAnchorsExtension) clone() TLSExtension {
	c := &TrustAnchorsExtension{}
	for _, id := range e.TrustAnchorIDs {
		c.TrustAnchorIDs = append(c.TrustAnchorIDs, cloneBytes(id))
	}
	return c
}
func (e *TrustAnchorsExtension) apply(b *helloBuild) error {
	for _, id := range e.TrustAnchorIDs {
		if len(id) == 0 || len(id) > 255 {
			return errors.New("utls: invalid trust anchor ID length")
		}
	}
	return nil
}
func (e *TrustAnchorsExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, id := range e.TrustAnchorIDs {
				b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(id) })
			}
		})
	})
	return body, true, err
}

// --- cookie (dynamic) -------------------------------------------------------------

// CookieExtension marks where the HelloRetryRequest cookie goes in a retried
// ClientHello (without it, the cookie is placed before padding).
type CookieExtension struct{}

func (e *CookieExtension) ID() uint16                 { return extensionCookie }
func (e *CookieExtension) clone() TLSExtension        { return &CookieExtension{} }
func (e *CookieExtension) apply(b *helloBuild) error { b.hasCookieSlot = true; return nil }
func (e *CookieExtension) render(r *helloRenderer, m *clientHelloMsg, _ int) ([]byte, bool, error) {
	if len(m.cookie) == 0 {
		return nil, false, nil
	}
	body, err := buildBody(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.cookie) })
	})
	return body, true, err
}

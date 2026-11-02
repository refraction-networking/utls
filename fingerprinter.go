// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"errors"

	"golang.org/x/crypto/cryptobyte"
)

// Fingerprinter turns a captured ClientHello into a ClientHelloSpec that
// reproduces its shape. Known extensions become their typed form (so the spec
// can be dialed with fresh key material and the caller's ServerName), and
// anything else is preserved verbatim as a GenericExtension.
//
// This replaces the per-project JA3/raw parsers the survey found in fastdialer,
// CycleTLS, fingerproxy and others.
type Fingerprinter struct {
	// AllowBluntMimicry keeps unknown extension bodies byte-for-byte. It is the
	// default behaviour; the field exists for API familiarity.
	AllowBluntMimicry bool
}

// ParseClientHello parses a raw ClientHello into a spec using default options.
// raw may be a full TLS record (starting 0x16 0x03 ...) or a bare handshake
// message (starting 0x01).
func ParseClientHello(raw []byte) (*ClientHelloSpec, error) {
	return (&Fingerprinter{}).FingerprintClientHello(raw)
}

// FingerprintClientHello parses raw into a ClientHelloSpec.
func (f *Fingerprinter) FingerprintClientHello(raw []byte) (*ClientHelloSpec, error) {
	body, err := clientHelloBody(raw)
	if err != nil {
		return nil, err
	}
	s := cryptobyte.String(body)

	var legacyVersion uint16
	var random, sessionID cryptobyte.String
	if !s.Skip(4) || // handshake type + uint24 length
		!s.ReadUint16(&legacyVersion) ||
		!s.ReadBytes((*[]byte)(&random), 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("utls: malformed ClientHello header")
	}

	spec := &ClientHelloSpec{}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil, errors.New("utls: malformed cipher_suites")
	}
	for !cipherSuites.Empty() {
		var cs uint16
		if !cipherSuites.ReadUint16(&cs) {
			return nil, errors.New("utls: malformed cipher_suites entry")
		}
		spec.CipherSuites = append(spec.CipherSuites, ungreaseCipher(cs))
	}

	var compression cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compression) {
		return nil, errors.New("utls: malformed compression_methods")
	}
	spec.CompressionMethods = append([]uint8(nil), []byte(compression)...)

	if s.Empty() {
		return spec, nil // no extensions
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		return nil, errors.New("utls: malformed extensions block")
	}
	for !exts.Empty() {
		var extType uint16
		var extData cryptobyte.String
		if !exts.ReadUint16(&extType) || !exts.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("utls: malformed extension")
		}
		spec.Extensions = append(spec.Extensions, parseExtension(extType, []byte(extData)))
	}
	return spec, nil
}

// clientHelloBody strips an optional TLS record header and returns the full
// handshake message (including its 4-byte header, matching the renderer).
func clientHelloBody(raw []byte) ([]byte, error) {
	if len(raw) < 4 {
		return nil, errors.New("utls: ClientHello too short")
	}
	// TLS record: content_type=22, version, uint16 length.
	if raw[0] == 0x16 && raw[1] == 0x03 {
		if len(raw) < 5 {
			return nil, errors.New("utls: truncated record")
		}
		recLen := int(raw[3])<<8 | int(raw[4])
		if 5+recLen > len(raw) {
			return nil, errors.New("utls: record length exceeds input")
		}
		raw = raw[5 : 5+recLen]
	}
	if len(raw) < 4 || raw[0] != 0x01 { // handshake type client_hello
		return nil, errors.New("utls: not a ClientHello")
	}
	return raw, nil
}

func ungreaseCipher(v uint16) uint16 {
	if isGREASE(v) {
		return GREASE_PLACEHOLDER
	}
	return v
}

func isGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v&0xff == v>>8
}

// parseExtension maps a captured extension to the richest typed form uTLS
// knows, so the resulting spec dials with fresh key material and the caller's
// SNI. Unknown extensions are preserved verbatim.
func parseExtension(extType uint16, data []byte) TLSExtension {
	if isGREASE(extType) {
		return &UtlsGREASEExtension{Value: extType, Body: data}
	}
	s := cryptobyte.String(data)
	switch extType {
	case 0: // server_name
		return &SNIExtension{}
	case 5: // status_request
		return &StatusRequestExtension{}
	case 10: // supported_groups
		var list cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&list) {
			break
		}
		var curves []CurveID
		for !list.Empty() {
			var g uint16
			if !list.ReadUint16(&g) {
				break
			}
			if isGREASE(g) {
				curves = append(curves, CurveID(GREASE_PLACEHOLDER))
			} else {
				curves = append(curves, CurveID(g))
			}
		}
		return &SupportedCurvesExtension{Curves: curves}
	case 11: // ec_point_formats
		var pts cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&pts) {
			break
		}
		return &SupportedPointsExtension{SupportedPoints: append([]byte(nil), []byte(pts)...)}
	case 13: // signature_algorithms
		if algs, ok := readSigAlgs(&s); ok {
			return &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: algs}
		}
	case 50: // signature_algorithms_cert
		if algs, ok := readSigAlgs(&s); ok {
			return &SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: algs}
		}
	case 16: // ALPN
		var list cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&list) {
			break
		}
		var protos []string
		for !list.Empty() {
			var p cryptobyte.String
			if !list.ReadUint8LengthPrefixed(&p) {
				break
			}
			protos = append(protos, string(p))
		}
		return &ALPNExtension{AlpnProtocols: protos}
	case 18:
		return &SCTExtension{}
	case 23:
		return &ExtendedMasterSecretExtension{}
	case 35:
		return &SessionTicketExtension{}
	case 43: // supported_versions
		var list cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&list) {
			break
		}
		var vers []uint16
		for !list.Empty() {
			var v uint16
			if !list.ReadUint16(&v) {
				break
			}
			if isGREASE(v) {
				vers = append(vers, GREASE_PLACEHOLDER)
			} else {
				vers = append(vers, v)
			}
		}
		return &SupportedVersionsExtension{Versions: vers}
	case 45: // psk_key_exchange_modes
		var modes cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&modes) {
			break
		}
		return &PSKKeyExchangeModesExtension{Modes: append([]byte(nil), []byte(modes)...)}
	case 51: // key_share
		var list cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&list) {
			break
		}
		var shares []KeyShareEntry
		for !list.Empty() {
			var g uint16
			var ks cryptobyte.String
			if !list.ReadUint16(&g) || !list.ReadUint16LengthPrefixed(&ks) {
				break
			}
			if isGREASE(g) {
				shares = append(shares, KeyShareEntry{Group: CurveID(GREASE_PLACEHOLDER), Data: []byte{0}})
			} else {
				// Fresh key for a known group; verbatim data otherwise.
				shares = append(shares, KeyShareEntry{Group: CurveID(g)})
			}
		}
		return &KeyShareExtension{KeyShares: shares}
	case 21: // padding
		return &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}
	case 27: // compress_certificate
		var algsB cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&algsB) {
			break
		}
		var algs []CertCompressionAlgo
		for !algsB.Empty() {
			var a uint16
			if !algsB.ReadUint16(&a) {
				break
			}
			algs = append(algs, CertCompressionAlgo(a))
		}
		return &CompressCertificateExtension{Algorithms: algs}
	case 28: // record_size_limit
		var lim uint16
		if s.ReadUint16(&lim) {
			return &RecordSizeLimitExtension{Limit: lim}
		}
	case 0xff01: // renegotiation_info
		return &RenegotiationInfoExtension{}
	}
	return &GenericExtension{Id: extType, Data: append([]byte(nil), data...)}
}

func readSigAlgs(s *cryptobyte.String) ([]SignatureScheme, bool) {
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) {
		return nil, false
	}
	var algs []SignatureScheme
	for !list.Empty() {
		var a uint16
		if !list.ReadUint16(&a) {
			return nil, false
		}
		algs = append(algs, SignatureScheme(a))
	}
	return algs, true
}

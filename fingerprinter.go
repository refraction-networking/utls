// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

// ParseClientHello builds a ClientHelloSpec from a captured ClientHello (a TLS
// record or a bare handshake message). The spec reproduces the capture's cipher
// suites, extension order and static extension contents. Values that must be
// fresh per connection are NOT replayed: GREASE values, key share data (keys
// are regenerated for the same groups), and handshake-owned extensions
// (pre_shared_key, early_data, cookie, encrypted_client_hello) become typed
// placeholders rendered from the live handshake. A captured
// encrypted_client_hello becomes a GREASE ECH of the same length.
func ParseClientHello(raw []byte) (*ClientHelloSpec, error) {
	body, err := clientHelloBody(raw)
	if err != nil {
		return nil, err
	}
	s := cryptobyte.String(body)
	var legacyVersion uint16
	var random, sessionID, cipherSuites, compression, exts cryptobyte.String
	if !s.Skip(4) || !s.ReadUint16(&legacyVersion) || !s.ReadBytes((*[]byte)(&random), 32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) || !s.ReadUint16LengthPrefixed(&cipherSuites) ||
		!s.ReadUint8LengthPrefixed(&compression) {
		return nil, errors.New("utls: malformed ClientHello")
	}
	spec := &ClientHelloSpec{CompressionMethods: append([]uint8(nil), compression...)}
	for !cipherSuites.Empty() {
		var cs uint16
		if !cipherSuites.ReadUint16(&cs) {
			return nil, errors.New("utls: malformed cipher_suites")
		}
		spec.CipherSuites = append(spec.CipherSuites, ungrease(cs))
	}
	if s.Empty() {
		spec.TLSVersMax = legacyVersion
		return spec, nil
	}
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return nil, errors.New("utls: malformed extensions block")
	}
	var hybridX25519 []byte
	for !exts.Empty() {
		var id uint16
		var data cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&data) {
			return nil, errors.New("utls: malformed extension")
		}
		ext, err := parseExtension(id, []byte(data), &hybridX25519)
		if err != nil {
			return nil, fmt.Errorf("utls: extension %d: %w", id, err)
		}
		spec.Extensions = append(spec.Extensions, ext)
	}
	if !hasExtension(spec, 43) {
		spec.TLSVersMax = min(legacyVersion, VersionTLS12)
	}
	return spec, spec.Validate()
}

func hasExtension(spec *ClientHelloSpec, id uint16) bool {
	for _, e := range spec.Extensions {
		if e.ID() == id {
			return true
		}
	}
	return false
}

func clientHelloBody(raw []byte) ([]byte, error) {
	if len(raw) >= 5 && raw[0] == 0x16 && raw[1] == 0x03 {
		recLen := int(raw[3])<<8 | int(raw[4])
		if 5+recLen > len(raw) {
			return nil, errors.New("utls: record length exceeds input")
		}
		raw = raw[5 : 5+recLen]
	}
	if len(raw) < 4 || raw[0] != 0x01 {
		return nil, errors.New("utls: not a ClientHello")
	}
	n := int(raw[1])<<16 | int(raw[2])<<8 | int(raw[3])
	if 4+n != len(raw) {
		return nil, errors.New("utls: ClientHello length mismatch (fragmented or truncated)")
	}
	return raw, nil
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v&0xff == v>>8 }

func ungrease(v uint16) uint16 {
	if isGREASE(v) {
		return GREASE_PLACEHOLDER
	}
	return v
}

func readU16List(s *cryptobyte.String) ([]uint16, bool) {
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
		return nil, false
	}
	var out []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return nil, false
		}
		out = append(out, ungrease(v))
	}
	return out, true
}

func readProtocols(s *cryptobyte.String) ([]string, bool) {
	var list cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
		return nil, false
	}
	var out []string
	for !list.Empty() {
		var p cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&p) || p.Empty() {
			return nil, false
		}
		out = append(out, string(p))
	}
	return out, true
}

var errBody = errors.New("malformed body")

func parseExtension(id uint16, data []byte, hybridX25519 *[]byte) (TLSExtension, error) {
	if isGREASE(id) {
		return &UtlsGREASEExtension{Body: append([]byte(nil), data...)}, nil
	}
	s := cryptobyte.String(data)
	switch id {
	case 0:
		return &SNIExtension{}, nil
	case 5:
		return &StatusRequestExtension{}, nil
	case 10:
		v, ok := readU16List(&s)
		if !ok {
			return nil, errBody
		}
		c := make([]CurveID, len(v))
		for i := range v {
			c[i] = CurveID(v[i])
		}
		return &SupportedCurvesExtension{Curves: c}, nil
	case 11:
		var pts cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&pts) || !s.Empty() {
			return nil, errBody
		}
		return &SupportedPointsExtension{SupportedPoints: append([]uint8(nil), pts...)}, nil
	case 13, 50:
		v, ok := readU16List(&s)
		if !ok {
			return nil, errBody
		}
		sa := make([]SignatureScheme, len(v))
		for i := range v {
			sa[i] = SignatureScheme(v[i])
		}
		if id == 13 {
			return &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sa}, nil
		}
		return &SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: sa}, nil
	case 16:
		ps, ok := readProtocols(&s)
		if !ok {
			return nil, errBody
		}
		return &ALPNExtension{AlpnProtocols: ps}, nil
	case 18:
		return &SCTExtension{}, nil
	case 21:
		return &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}, nil
	case 23:
		return &ExtendedMasterSecretExtension{}, nil
	case 27:
		var list cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&list) || !s.Empty() {
			return nil, errBody
		}
		var algs []CertCompressionAlgo
		for !list.Empty() {
			var a uint16
			if !list.ReadUint16(&a) {
				return nil, errBody
			}
			algs = append(algs, CertCompressionAlgo(a))
		}
		return &CompressCertificateExtension{Algorithms: algs}, nil
	case 28:
		var lim uint16
		if !s.ReadUint16(&lim) || !s.Empty() {
			return nil, errBody
		}
		return &RecordSizeLimitExtension{Limit: lim}, nil
	case 35:
		return &SessionTicketExtension{}, nil
	case 41:
		return &PreSharedKeyExtension{}, nil
	case 42:
		return &EarlyDataExtension{}, nil
	case 43:
		var list cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&list) || !s.Empty() {
			return nil, errBody
		}
		var vers []uint16
		for !list.Empty() {
			var v uint16
			if !list.ReadUint16(&v) {
				return nil, errBody
			}
			vers = append(vers, ungrease(v))
		}
		return &SupportedVersionsExtension{Versions: vers}, nil
	case 44:
		return &CookieExtension{}, nil
	case 45:
		var modes cryptobyte.String
		if !s.ReadUint8LengthPrefixed(&modes) || !s.Empty() {
			return nil, errBody
		}
		return &PSKKeyExchangeModesExtension{Modes: append([]uint8(nil), modes...)}, nil
	case 51:
		var list cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
			return nil, errBody
		}
		ks := &KeyShareExtension{}
		for !list.Empty() {
			var g uint16
			var d cryptobyte.String
			if !list.ReadUint16(&g) || !list.ReadUint16LengthPrefixed(&d) {
				return nil, errBody
			}
			switch {
			case isGREASE(g):
				ks.KeyShares = append(ks.KeyShares, KeyShareEntry{Group: GREASE_PLACEHOLDER, Data: append([]byte(nil), d...)})
			default:
				if CurveID(g) == X25519MLKEM768 && len(d) >= 32 {
					*hybridX25519 = append([]byte(nil), d[len(d)-32:]...)
				}
				if CurveID(g) == X25519 && *hybridX25519 != nil && bytes.Equal(d, *hybridX25519) {
					ks.ReuseClassicalFromHybrid = true
				}
				ks.KeyShares = append(ks.KeyShares, KeyShareEntry{Group: CurveID(g)})
			}
		}
		return ks, nil
	case 57:
		return &QUICTransportParametersExtension{}, nil
	case 17513, 17613:
		ps, ok := readProtocols(&s)
		if !ok {
			return nil, errBody
		}
		return &ApplicationSettingsExtension{SupportedProtocols: ps, CodePoint: id}, nil
	case 0xca34:
		var list cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&list) || !s.Empty() {
			return nil, errBody
		}
		ta := &TrustAnchorsExtension{}
		for !list.Empty() {
			var v cryptobyte.String
			if !list.ReadUint8LengthPrefixed(&v) || v.Empty() {
				return nil, errBody
			}
			ta.TrustAnchorIDs = append(ta.TrustAnchorIDs, append([]byte(nil), v...))
		}
		return ta, nil
	case 0xfe0d:
		var typ uint8
		var kdf, aead uint16
		var cfgID uint8
		var enc, payload cryptobyte.String
		if !s.ReadUint8(&typ) || typ != 0 || !s.ReadUint16(&kdf) || !s.ReadUint16(&aead) || !s.ReadUint8(&cfgID) ||
			!s.ReadUint16LengthPrefixed(&enc) || !s.ReadUint16LengthPrefixed(&payload) || !s.Empty() {
			return nil, errBody
		}
		return &EncryptedClientHelloExtension{GREASE: true,
			GREASECipherSuites:   []HPKESymmetricCipherSuite{{KDF: kdf, AEAD: aead}},
			GREASEPayloadLengths: []uint16{uint16(len(payload))}}, nil
	case 0xff01:
		return &RenegotiationInfoExtension{}, nil
	}
	return &GenericExtension{Id: id, Data: append([]byte(nil), data...)}, nil
}

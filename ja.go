// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/cryptobyte"
)

// JA3 computes the JA3 string and MD5 hash of a raw ClientHello (record or
// handshake message), ignoring GREASE values as JA3 specifies.
func JA3(raw []byte) (text, hash string, err error) {
	h, err := parseRawHello(raw)
	if err != nil {
		return "", "", err
	}
	join := func(v []uint16) string {
		var parts []string
		for _, x := range v {
			if !isGREASE(x) {
				parts = append(parts, strconv.Itoa(int(x)))
			}
		}
		return strings.Join(parts, "-")
	}
	var pts []string
	for _, p := range h.points {
		pts = append(pts, strconv.Itoa(int(p)))
	}
	text = fmt.Sprintf("%d,%s,%s,%s,%s", h.legacyVersion, join(h.ciphers), join(h.extIDs), join(h.groups), strings.Join(pts, "-"))
	sum := md5.Sum([]byte(text))
	return text, hex.EncodeToString(sum[:]), nil
}

// JA4 computes the JA4 fingerprint (TLS over TCP, "t" prefix) of a raw
// ClientHello. JA4 hashes sorted cipher and extension lists, so it cannot be
// turned back into a ClientHello; uTLS offers no JA4 input.
func JA4(raw []byte) (string, error) {
	h, err := parseRawHello(raw)
	if err != nil {
		return "", err
	}
	// TLS version (JA4 spec, "TLS and DTLS Version"): if supported_versions
	// is present, the highest non-GREASE value in it — even if lower than
	// legacy_version, and "00" if it lists none or only unknown values;
	// legacy_version only when the extension is absent.
	ver := h.legacyVersion
	if h.hasVersions {
		ver = 0
		for _, v := range h.versions {
			if !isGREASE(v) && v > ver {
				ver = v
			}
		}
	}
	verStr := ja4Versions[ver]
	if verStr == "" {
		verStr = "00"
	}
	sni := "i"
	if h.hasSNI {
		sni = "d"
	}
	var ciphers, exts []uint16
	for _, c := range h.ciphers {
		if !isGREASE(c) {
			ciphers = append(ciphers, c)
		}
	}
	for _, e := range h.extIDs {
		if !isGREASE(e) {
			exts = append(exts, e)
		}
	}
	alpn := ja4ALPN(h.alpn)
	hexList := func(v []uint16) string {
		var parts []string
		for _, x := range v {
			parts = append(parts, fmt.Sprintf("%04x", x))
		}
		return strings.Join(parts, ",")
	}
	hash12 := func(s string) string {
		if s == "" {
			return "000000000000"
		}
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])[:12]
	}
	sc := slices.Clone(ciphers)
	sort.Slice(sc, func(i, j int) bool { return sc[i] < sc[j] })
	var se []uint16
	for _, e := range exts {
		if e != 0 && e != 16 { // SNI and ALPN are excluded from the extension hash
			se = append(se, e)
		}
	}
	sort.Slice(se, func(i, j int) bool { return se[i] < se[j] })
	var sigs []uint16
	for _, s := range h.sigalgs {
		if !isGREASE(s) {
			sigs = append(sigs, s)
		}
	}
	extPart := hexList(se)
	if len(sigs) > 0 {
		extPart += "_" + hexList(sigs)
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", verStr, sni, min(len(ciphers), 99), min(len(exts), 99), alpn)
	return a + "_" + hash12(hexList(sc)) + "_" + hash12(extPart), nil
}

var ja4Versions = map[uint16]string{
	0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
	0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3",
}

// ja4ALPN is JA4's two-character ALPN field (spec, "ALPN Extension Value"):
// "00" without ALPN or with an empty first value; the first and last bytes of
// the first value when both are ASCII alphanumeric (a single byte counts as
// both); otherwise the first and last hex digits of the whole first value.
func ja4ALPN(protos [][]byte) string {
	if len(protos) == 0 || len(protos[0]) == 0 {
		return "00"
	}
	a := protos[0]
	alnum := func(c byte) bool { return '0' <= c && c <= '9' || 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' }
	if alnum(a[0]) && alnum(a[len(a)-1]) {
		return string([]byte{a[0], a[len(a)-1]})
	}
	x := hex.EncodeToString(a)
	return string([]byte{x[0], x[len(x)-1]})
}

type rawHello struct {
	legacyVersion uint16
	ciphers       []uint16
	extIDs        []uint16
	groups        []uint16
	points        []uint8
	versions      []uint16
	hasVersions   bool // supported_versions present (versions may still be empty)
	sigalgs       []uint16
	alpn          [][]byte
	hasSNI        bool
}

func parseRawHello(raw []byte) (*rawHello, error) {
	body, err := clientHelloBody(raw)
	if err != nil {
		return nil, err
	}
	h := &rawHello{}
	s := cryptobyte.String(body)
	var random, sid, cs, comp, exts cryptobyte.String
	if !s.Skip(4) || !s.ReadUint16(&h.legacyVersion) || !s.ReadBytes((*[]byte)(&random), 32) ||
		!s.ReadUint8LengthPrefixed(&sid) || !s.ReadUint16LengthPrefixed(&cs) || !s.ReadUint8LengthPrefixed(&comp) {
		return nil, errors.New("utls: malformed ClientHello")
	}
	for !cs.Empty() {
		var c uint16
		if !cs.ReadUint16(&c) {
			return nil, errors.New("utls: malformed cipher_suites")
		}
		h.ciphers = append(h.ciphers, c)
	}
	if s.Empty() {
		return h, nil
	}
	if !s.ReadUint16LengthPrefixed(&exts) || !s.Empty() {
		return nil, errors.New("utls: malformed extensions")
	}
	for !exts.Empty() {
		var id uint16
		var d cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&d) {
			return nil, errors.New("utls: malformed extension")
		}
		h.extIDs = append(h.extIDs, id)
		var ok bool
		switch id {
		case 0:
			h.hasSNI = true
		case 10:
			if h.groups, ok = readRawU16List(d); !ok {
				return nil, errors.New("utls: malformed supported_groups")
			}
		case 11:
			var p cryptobyte.String
			if !d.ReadUint8LengthPrefixed(&p) || !d.Empty() {
				return nil, errors.New("utls: malformed ec_point_formats")
			}
			h.points = append([]uint8(nil), p...)
		case 13:
			if h.sigalgs, ok = readRawU16List(d); !ok {
				return nil, errors.New("utls: malformed signature_algorithms")
			}
		case 16:
			if h.alpn, ok = readRawProtocols(d); !ok {
				return nil, errors.New("utls: malformed application_layer_protocol_negotiation")
			}
		case 43:
			h.hasVersions = true
			var list cryptobyte.String
			if !d.ReadUint8LengthPrefixed(&list) || !d.Empty() {
				return nil, errors.New("utls: malformed supported_versions")
			}
			for !list.Empty() {
				var v uint16
				if !list.ReadUint16(&v) {
					return nil, errors.New("utls: malformed supported_versions")
				}
				h.versions = append(h.versions, v)
			}
		}
	}
	return h, nil
}

// readRawProtocols reads an ALPN protocol_name_list without judging the
// names (JA4 defines output for empty and binary names).
func readRawProtocols(d cryptobyte.String) ([][]byte, bool) {
	var list cryptobyte.String
	if !d.ReadUint16LengthPrefixed(&list) || !d.Empty() {
		return nil, false
	}
	var out [][]byte
	for !list.Empty() {
		var p cryptobyte.String
		if !list.ReadUint8LengthPrefixed(&p) {
			return nil, false
		}
		out = append(out, append([]byte(nil), p...))
	}
	return out, true
}

func readRawU16List(d cryptobyte.String) ([]uint16, bool) {
	var list cryptobyte.String
	if !d.ReadUint16LengthPrefixed(&list) || !d.Empty() {
		return nil, false
	}
	var out []uint16
	for !list.Empty() {
		var v uint16
		if !list.ReadUint16(&v) {
			return nil, false
		}
		out = append(out, v)
	}
	return out, true
}

// JA3SpecOptions supply what a JA3 string does not record. A JA3 string fixes
// the legacy version, cipher order, extension ORDER, groups and point formats,
// but not extension contents: SpecFromJA3 fills those from these options and
// from uTLS defaults, so the result has the given JA3 but is not a byte copy of
// the hello it came from.
type JA3SpecOptions struct {
	SignatureAlgorithms []SignatureScheme // default: Chrome's list
	ALPN                []string          // default: h2, http/1.1
	Versions            []uint16          // supported_versions; default: TLS 1.3, TLS 1.2
	KeyShareGroups      []CurveID         // default: first non-GREASE group
	CertCompression     []CertCompressionAlgo
}

// SpecFromJA3 builds a spec whose rendered ClientHello has the given JA3 string
// (not hash: a hash cannot be inverted). Extensions are created only for code
// points whose contents uTLS can derive; any other code point is an error, so
// a JA3 is never satisfied with invented extension bodies.
func SpecFromJA3(ja3 string, o JA3SpecOptions) (*ClientHelloSpec, error) {
	f := strings.Split(ja3, ",")
	if len(f) != 5 {
		return nil, errors.New("utls: JA3 string must have 5 comma-separated fields")
	}
	nums := func(s string) ([]uint16, error) {
		if s == "" {
			return nil, nil
		}
		var out []uint16
		for _, p := range strings.Split(s, "-") {
			v, err := strconv.ParseUint(p, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("utls: bad JA3 number %q", p)
			}
			out = append(out, uint16(v))
		}
		return out, nil
	}
	vers, err := nums(f[0])
	if err != nil || len(vers) != 1 {
		return nil, errors.New("utls: bad JA3 version")
	}
	ciphers, err := nums(f[1])
	if err != nil {
		return nil, err
	}
	extIDs, err := nums(f[2])
	if err != nil {
		return nil, err
	}
	groups, err := nums(f[3])
	if err != nil {
		return nil, err
	}
	points, err := nums(f[4])
	if err != nil {
		return nil, err
	}
	sigs := o.SignatureAlgorithms
	if sigs == nil {
		sigs = []SignatureScheme{ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256, ECDSAWithP384AndSHA384, PSSWithSHA384, PKCS1WithSHA384, PSSWithSHA512, PKCS1WithSHA512}
	}
	alpn := o.ALPN
	if alpn == nil {
		alpn = []string{"h2", "http/1.1"}
	}
	versions := o.Versions
	if versions == nil {
		versions = []uint16{VersionTLS13, VersionTLS12}
	}
	var curves []CurveID
	for _, g := range groups {
		curves = append(curves, CurveID(g))
	}
	shareGroups := o.KeyShareGroups
	if shareGroups == nil && len(curves) > 0 {
		shareGroups = curves[:1]
	}
	spec := &ClientHelloSpec{CipherSuites: ciphers, CompressionMethods: []uint8{0}}
	for _, id := range extIDs {
		var e TLSExtension
		switch id {
		case 0:
			e = &SNIExtension{}
		case 5:
			e = &StatusRequestExtension{}
		case 10:
			e = &SupportedCurvesExtension{Curves: curves}
		case 11:
			var pts []uint8
			for _, p := range points {
				pts = append(pts, uint8(p))
			}
			e = &SupportedPointsExtension{SupportedPoints: pts}
		case 13:
			e = &SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: sigs}
		case 16:
			e = &ALPNExtension{AlpnProtocols: alpn}
		case 18:
			e = &SCTExtension{}
		case 21:
			e = &UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle}
		case 23:
			e = &ExtendedMasterSecretExtension{}
		case 27:
			algs := o.CertCompression
			if algs == nil {
				algs = []CertCompressionAlgo{CertCompressionBrotli}
			}
			e = &CompressCertificateExtension{Algorithms: algs}
		case 35:
			e = &SessionTicketExtension{}
		case 41:
			e = &PreSharedKeyExtension{}
		case 43:
			e = &SupportedVersionsExtension{Versions: versions}
		case 45:
			e = &PSKKeyExchangeModesExtension{Modes: []uint8{pskModeDHE}}
		case 51:
			ks := &KeyShareExtension{}
			for _, g := range shareGroups {
				ks.KeyShares = append(ks.KeyShares, KeyShareEntry{Group: g})
			}
			e = ks
		case 0xff01:
			e = &RenegotiationInfoExtension{}
		case 0xfe0d:
			e = &EncryptedClientHelloExtension{GREASE: true}
		default:
			return nil, fmt.Errorf("utls: JA3 extension %d has contents uTLS cannot derive from a JA3 string; build that spec explicitly", id)
		}
		spec.Extensions = append(spec.Extensions, e)
	}
	if vers[0] < VersionTLS12 && !slices.Contains(extIDs, 43) {
		spec.TLSVersMax = vers[0]
	}
	return spec, spec.Validate()
}

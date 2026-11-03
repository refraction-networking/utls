// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"

	"golang.org/x/crypto/cryptobyte"
)

// ClientHelloSpec is the complete description of a ClientHello's shape: the
// cipher suites and compression methods offered and the ordered extension list.
//
// Precedence between a spec and the Config (documented in docs/API_DESIGN.md):
//   - Versions: offered = spec supported_versions ∩ Config Min/MaxVersion ∩
//     [TLSVersMin, TLSVersMax]; empty is an error. A spec without
//     supported_versions offers at most TLS 1.2.
//   - Cipher suites: spec order; Config.CipherSuites, when set, removes TLS 1.0-1.2
//     suites not listed (as in crypto/tls, TLS 1.3 suites are not configurable).
//   - Groups and key shares: spec order; Config.CurvePreferences, when set,
//     removes groups not listed.
//   - ALPN: Config.NextProtos, when set, replaces the spec's ALPN list; a spec
//     without an ALPN extension plus a non-empty NextProtos is an error.
//   - SNI: SNIExtension.ServerName, else Config.ServerName; IP literals and
//     empty names omit the extension.
//   - Session tickets: Config.SessionTicketsDisabled omits session_ticket.
//
// A spec is copied when attached to a connection; later changes to it do not
// affect that connection.
type ClientHelloSpec struct {
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []TLSExtension

	// TLSVersMin and TLSVersMax, when non-zero, bound the offered versions in
	// addition to the Config.
	TLSVersMin uint16
	TLSVersMax uint16
}

// Clone returns a deep copy of the spec.
func (s *ClientHelloSpec) Clone() *ClientHelloSpec {
	if s == nil {
		return nil
	}
	c := &ClientHelloSpec{
		CipherSuites:       slices.Clone(s.CipherSuites),
		CompressionMethods: slices.Clone(s.CompressionMethods),
		TLSVersMin:         s.TLSVersMin,
		TLSVersMax:         s.TLSVersMax,
	}
	for _, e := range s.Extensions {
		if isNilExtension(e) {
			c.Extensions = append(c.Extensions, nil) // rejected by Validate
			continue
		}
		c.Extensions = append(c.Extensions, e.clone())
	}
	return c
}

// Validate checks the spec for structural errors without a connection.
func (s *ClientHelloSpec) Validate() error {
	if s == nil {
		return ErrNoSpec
	}
	if len(s.CipherSuites) == 0 {
		return errors.New("utls: spec has no cipher suites")
	}
	if len(s.CompressionMethods) == 0 || !slices.Contains(s.CompressionMethods, compressionNone) {
		return errors.New("utls: spec compression methods must include null (0)")
	}
	if len(s.CipherSuites) > 0x7fff || len(s.CompressionMethods) > 0xff {
		return errors.New("utls: spec cipher suite or compression list too long")
	}
	seen := map[uint16]bool{}
	greaseCount := 0
	for i, e := range s.Extensions {
		if isNilExtension(e) {
			return fmt.Errorf("utls: spec extension %d is nil", i)
		}
		id := e.ID()
		if g, ok := e.(*UtlsGREASEExtension); ok {
			greaseCount++
			if g.Value != 0 {
				if seen[g.Value] {
					return fmt.Errorf("utls: duplicate GREASE extension value %#04x", g.Value)
				}
				seen[g.Value] = true
			}
			continue
		}
		if seen[id] {
			return fmt.Errorf("utls: duplicate extension %d in spec", id)
		}
		seen[id] = true
	}
	if greaseCount > 8 {
		return errors.New("utls: too many GREASE extensions")
	}
	if s.TLSVersMin != 0 && s.TLSVersMax != 0 && s.TLSVersMin > s.TLSVersMax {
		return errors.New("utls: TLSVersMin > TLSVersMax")
	}
	return nil
}

// helloBuild is the build stage: it turns a spec plus the Config into the
// logical ClientHello and a renderer.
type helloBuild struct {
	c      *Conn
	config *Config
	hello  *clientHelloMsg
	spec   *ClientHelloSpec

	hasSNI, hasALPN, hasTicket, hasECHSlot, hasCookieSlot, hasQUICSlot bool

	specVersions    []uint16
	keyShareSpec    *KeyShareExtension
	pskModes        []uint8
	echSlot         *EncryptedClientHelloExtension
	alps            *ApplicationSettingsExtension
	certCompression []CertCompressionAlgo
	recordSizeLimit uint16
}

func (b *helloBuild) groupAllowed(g CurveID) bool {
	if len(b.config.CurvePreferences) == 0 {
		return true
	}
	return slices.Contains(b.config.CurvePreferences, g)
}

// greaseValues are the per-connection GREASE values, one per slot as in
// BoringSSL. The key_share GREASE group equals the supported_groups one.
type greaseValues struct {
	cipher, group, version, sigalg uint16
	ext                            map[int]uint16 // spec index -> value
}

func greaseFrom(b byte) uint16 {
	v := uint16(b&0xf0) | 0x0a
	return v<<8 | v
}

// build applies the spec to the logical hello crypto/tls created. It returns
// the private keys of every generated key share keyed by group, and the
// primary (first generated) one.
func (b *helloBuild) build() (map[CurveID]*keySharePrivateKeys, *keySharePrivateKeys, error) {
	if err := b.spec.Validate(); err != nil {
		return nil, nil, err
	}
	h, cfg := b.hello, b.config
	goVersions := h.supportedVersions // Config-allowed versions, highest first
	echActive := h.encryptedClientHello != nil

	// Reset what the spec decides.
	h.extendedMasterSecret = false
	h.ocspStapling = false
	h.scts = false
	h.supportedPoints = nil
	h.secureRenegotiationSupported = false
	h.ticketSupported = false
	h.supportedSignatureAlgorithms = nil
	h.supportedSignatureAlgorithmsCert = nil
	h.pskModes = nil
	h.supportedCurves = nil
	h.keyShares = nil
	h.alpnProtocols = slices.Clone(cfg.NextProtos)

	for _, e := range b.spec.Extensions {
		if err := e.apply(b); err != nil {
			return nil, nil, err
		}
	}
	if !b.hasSNI {
		h.serverName = ""
	}
	if len(cfg.NextProtos) > 0 && !b.hasALPN {
		return nil, nil, errors.New("utls: Config.NextProtos is set but the ClientHelloSpec has no ALPN extension")
	}

	// Versions.
	src := b.specVersions
	if src == nil {
		src = []uint16{VersionTLS12, VersionTLS11, VersionTLS10}
	}
	var offered []uint16
	for _, v := range src {
		if isGREASEUint16(v) || !slices.Contains(goVersions, v) {
			continue
		}
		if (b.spec.TLSVersMin != 0 && v < b.spec.TLSVersMin) || (b.spec.TLSVersMax != 0 && v > b.spec.TLSVersMax) {
			continue
		}
		offered = append(offered, v)
	}
	if len(offered) == 0 {
		return nil, nil, errors.New("utls: no TLS version is allowed by both the ClientHelloSpec and the Config")
	}
	h.supportedVersions = offered
	maxV := slices.Max(offered)
	if b.recordSizeLimit > maxPlaintext && maxV < VersionTLS13 {
		return nil, nil, fmt.Errorf("utls: record_size_limit %d exceeds the TLS 1.2 maximum of %d", b.recordSizeLimit, maxPlaintext)
	}
	h.vers = min(maxV, VersionTLS12) // RFC 8446 4.1.2: legacy_version is at most 0x0303
	if echActive && maxV < VersionTLS13 {
		return nil, nil, errors.New("utls: Encrypted Client Hello requires the spec to offer TLS 1.3")
	}

	// Cipher suites.
	h.cipherSuites = nil
	for _, cs := range b.spec.CipherSuites {
		if isGREASEUint16(cs) {
			continue
		}
		if len(cfg.CipherSuites) > 0 && cipherSuiteTLS13ByID(cs) == nil && !slices.Contains(cfg.CipherSuites, cs) {
			continue
		}
		h.cipherSuites = append(h.cipherSuites, cs)
	}
	if len(h.cipherSuites) == 0 {
		return nil, nil, errors.New("utls: no cipher suite left after applying Config.CipherSuites")
	}
	h.compressionMethods = slices.Clone(b.spec.CompressionMethods)

	// Key shares.
	keys := map[CurveID]*keySharePrivateKeys{}
	var primary *keySharePrivateKeys
	if maxV >= VersionTLS13 {
		if b.keyShareSpec == nil {
			return nil, nil, errors.New("utls: the spec offers TLS 1.3 but has no key_share extension")
		}
		for _, ks := range b.keyShareSpec.KeyShares {
			if isGREASEUint16(uint16(ks.Group)) {
				continue
			}
			if len(ks.Data) > 0 {
				return nil, nil, fmt.Errorf("utls: key share for group %v has explicit Data but no private key; leave Data empty to generate it", ks.Group)
			}
			if !b.groupAllowed(ks.Group) || !slices.Contains(h.supportedCurves, ks.Group) {
				continue
			}
			if keys[ks.Group] != nil {
				return nil, nil, fmt.Errorf("utls: duplicate key share for group %v", ks.Group)
			}
			if ks.Group == X25519 && b.keyShareSpec.ReuseClassicalFromHybrid && keys[X25519MLKEM768] != nil {
				hk := keys[X25519MLKEM768].ecdhe
				h.keyShares = append(h.keyShares, keyShare{group: X25519, data: hk.PublicKey().Bytes()})
				keys[X25519] = &keySharePrivateKeys{ecdhe: hk}
				continue
			}
			ke, err := keyExchangeForCurveID(ks.Group)
			if err != nil {
				return nil, nil, fmt.Errorf("utls: cannot generate a key share for group %v: %v", ks.Group, err)
			}
			priv, shares, err := ke.keyShares(cfg.rand())
			if err != nil {
				return nil, nil, err
			}
			h.keyShares = append(h.keyShares, shares[0]) // shares[1] is a fallback the spec lists separately
			keys[ks.Group] = priv
			if primary == nil {
				primary = priv
			}
		}
		if primary == nil {
			return nil, nil, errors.New("utls: no key share left for TLS 1.3 after applying Config.CurvePreferences")
		}
	}

	if echActive {
		// The inner hello is TLS 1.3 only, as crypto/tls makes it. The outer
		// hello still renders these extensions from the spec (legacyEmit).
		h.supportedPoints = nil
		h.ticketSupported = false
		h.secureRenegotiationSupported = false
		h.extendedMasterSecret = false
	}
	if b.c.handshakes > 0 {
		h.secureRenegotiationSupported = true
	}
	return keys, primary, nil
}

// helloRenderer serializes a clientHelloMsg in the spec's shape. It holds the
// per-connection state that must be identical across every ClientHello of the
// connection (GREASE values, GREASE ECH payload), and nothing else: all
// handshake-owned values are read from the message being rendered.
type helloRenderer struct {
	owner           *UConn
	owned           *clientHelloMsg // the connection's (outer) hello; snapshots are taken of it
	spec            *ClientHelloSpec
	grease          greaseValues
	echGREASE       []byte
	firstGroups     []CurveID // key share groups of the first ClientHello
	ticketsDisabled bool
	hasCookieSlot   bool
	hasECHSlot      bool
	hasQUICSlot     bool
	hasEarlySlot    bool
	padding         *UtlsPaddingExtension
	padLen          int
}

func newHelloRenderer(spec *ClientHelloSpec, b *helloBuild, rand io.Reader) (*helloRenderer, error) {
	r := &helloRenderer{
		spec:            spec,
		ticketsDisabled: b.config.SessionTicketsDisabled,
		hasCookieSlot:   b.hasCookieSlot,
		hasECHSlot:      b.hasECHSlot,
		hasQUICSlot:     b.hasQUICSlot,
		padLen:          -1,
	}
	var seed [64]byte
	if _, err := io.ReadFull(rand, seed[:]); err != nil {
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}
	r.grease = greaseValues{
		cipher:  greaseFrom(seed[0]),
		group:   greaseFrom(seed[1]),
		version: greaseFrom(seed[2]),
		sigalg:  greaseFrom(seed[3]),
		ext:     map[int]uint16{},
	}
	// GREASE extension code points must be distinct across ALL slots (an
	// extension type may appear only once): fixed Values are reserved first,
	// drawn ones take the next unused value.
	used := map[uint16]bool{}
	for _, e := range spec.Extensions {
		if g, ok := e.(*UtlsGREASEExtension); ok && g.Value != 0 {
			used[g.Value] = true
		}
	}
	n := 0
	for i, e := range spec.Extensions {
		switch e := e.(type) {
		case *UtlsGREASEExtension:
			v := e.Value
			if v == 0 {
				v = greaseFrom(seed[4+n])
				for used[v] {
					v = greaseFrom(byte(v>>8) + 0x10)
				}
				used[v] = true
			}
			r.grease.ext[i] = v
			n++
		case *UtlsPaddingExtension:
			if r.padding == nil {
				r.padding = e
			}
		case *EarlyDataExtension:
			r.hasEarlySlot = true
		}
	}
	for _, ks := range b.hello.keyShares {
		r.firstGroups = append(r.firstGroups, ks.group)
	}
	// GREASE ECH (BoringSSL shape by default): config_id, HPKE suite, 32-byte
	// enc and a payload of 144 + 32*k bytes, k in [0,3].
	payloadLen := 144 + 32*int(seed[20]&3)
	suite := HPKESymmetricCipherSuite{KDF: 1, AEAD: 1}
	if e := b.echSlot; e != nil {
		if len(e.GREASEPayloadLengths) > 0 {
			payloadLen = int(e.GREASEPayloadLengths[int(seed[22])%len(e.GREASEPayloadLengths)])
		}
		if len(e.GREASECipherSuites) > 0 {
			suite = e.GREASECipherSuites[int(seed[23])%len(e.GREASECipherSuites)]
		}
	}
	ech := make([]byte, 0, 10+32+payloadLen)
	ech = append(ech, 0) // ClientHelloOuter
	ech = append(ech, byte(suite.KDF>>8), byte(suite.KDF), byte(suite.AEAD>>8), byte(suite.AEAD))
	ech = append(ech, seed[21]) // config_id
	ech = append(ech, 0x00, 32) // enc length
	ech = append(ech, make([]byte, 32)...)
	ech = append(ech, byte(payloadLen>>8), byte(payloadLen))
	ech = append(ech, make([]byte, payloadLen)...)
	if _, err := io.ReadFull(rand, ech[8:8+32]); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand, ech[8+32+2:]); err != nil {
		return nil, err
	}
	r.echGREASE = ech
	return r, nil
}

// isRetry reports whether m is the ClientHello sent after a HelloRetryRequest
// that asked for a different key share.
func (r *helloRenderer) isRetry(m *clientHelloMsg) bool {
	if len(m.keyShares) != len(r.firstGroups) {
		return true
	}
	for i, ks := range m.keyShares {
		if ks.group != r.firstGroups[i] {
			return true
		}
	}
	return false
}

// marshal renders m. encodedInner selects the EncodedClientHelloInner form
// (empty legacy_session_id) used inside ECH; the server restores the session
// ID from the outer hello, so the inner transcript matches marshal(m, false).
func (r *helloRenderer) marshal(m *clientHelloMsg, encodedInner bool) ([]byte, error) {
	out, err := r.marshalPadded(m, encodedInner)
	if err == nil && !encodedInner && m == r.owned && r.owner != nil {
		r.owner.setSnapshot(out)
	}
	return out, err
}

func (r *helloRenderer) marshalPadded(m *clientHelloMsg, encodedInner bool) ([]byte, error) {
	r.padLen = -1
	out, err := r.assemble(m, encodedInner)
	if err != nil || r.padding == nil {
		return out, err
	}
	get := r.padding.GetPaddingLen
	if get == nil {
		get = BoringPaddingStyle
	}
	unpadded := len(out)
	if encodedInner {
		// Pad as the full ClientHelloInner (with its session ID): the server
		// reconstructs that form, and the inner transcript must match it.
		unpadded += len(m.sessionId)
	}
	if n, will := get(unpadded); will {
		if n < 0 || n > 0xffff {
			return nil, errors.New("utls: invalid padding length")
		}
		r.padLen = n
		out, err = r.assemble(m, encodedInner)
	}
	r.padLen = -1
	return out, err
}

func (r *helloRenderer) assemble(m *clientHelloMsg, encodedInner bool) ([]byte, error) {
	if len(m.random) != 32 {
		return nil, errors.New("utls: ClientHello random must be 32 bytes")
	}
	if len(m.sessionId) > 32 {
		return nil, errors.New("utls: ClientHello session ID longer than 32 bytes")
	}
	var renderErr error
	b := cryptobyte.NewBuilder(nil)
	b.AddUint8(typeClientHello)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.vers)
		b.AddBytes(m.random)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
			if !encodedInner {
				b.AddBytes(m.sessionId)
			}
		})
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, cs := range r.spec.CipherSuites {
				if isGREASEUint16(cs) {
					b.AddUint16(r.grease.cipher)
				} else if slices.Contains(m.cipherSuites, cs) {
					b.AddUint16(cs)
				}
			}
		})
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.compressionMethods) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			add := func(id uint16, body []byte) {
				b.AddUint16(id)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
			}
			dynamicDone := false
			dynamic := func() {
				if dynamicDone {
					return
				}
				dynamicDone = true
				if len(m.cookie) > 0 && !r.hasCookieSlot {
					body, _, err := (&CookieExtension{}).render(r, m, -1)
					if err != nil {
						renderErr = err
					}
					add(extensionCookie, body)
				}
				if m.earlyData && !r.hasEarlySlot {
					add(extensionEarlyData, nil)
				}
				if len(m.encryptedClientHello) > 0 && !r.hasECHSlot {
					add(extensionEncryptedClientHello, m.encryptedClientHello)
				}
				if m.quicTransportParameters != nil && !r.hasQUICSlot {
					add(extensionQUICTransportParameters, m.quicTransportParameters)
				}
			}
			for i, e := range r.spec.Extensions {
				if _, ok := e.(*UtlsPaddingExtension); ok {
					dynamic() // handshake-added extensions go before padding
				}
				body, emit, err := e.render(r, m, i)
				if err != nil {
					renderErr = err
					return
				}
				if !emit {
					continue
				}
				id := e.ID()
				if _, ok := e.(*UtlsGREASEExtension); ok {
					id = r.grease.ext[i]
				}
				add(id, body)
			}
			dynamic()
			// pre_shared_key MUST be the last extension (RFC 8446 4.2.11). As in
			// crypto/tls, it is never sent in an ECH outer hello.
			if len(m.pskIdentities) > 0 && (encodedInner || len(m.encryptedClientHello) == 0 || isECHInner(m)) {
				b.AddUint16(extensionPreSharedKey)
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, psk := range m.pskIdentities {
							b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(psk.label) })
							b.AddUint32(psk.obfuscatedTicketAge)
						}
					})
					b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
						for _, binder := range m.pskBinders {
							b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(binder) })
						}
					})
				})
			}
		})
	})
	if renderErr != nil {
		return nil, renderErr
	}
	return b.Bytes()
}

// isNilExtension reports a nil interface or a typed nil pointer.
func isNilExtension(e TLSExtension) bool {
	if e == nil {
		return true
	}
	v := reflect.ValueOf(e)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

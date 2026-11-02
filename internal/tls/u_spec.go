// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/rand"
	"errors"
	"io"
)

// ClientHelloSpec is the complete description of a ClientHello's wire shape:
// which cipher suites and compression methods to offer, and the exact ordered
// list of extensions. It is the single source of truth the renderer uses; a
// fingerprint preset is just a function that returns one.
type ClientHelloSpec struct {
	CipherSuites       []uint16
	CompressionMethods []uint8
	Extensions         []TLSExtension

	// TLSVersMin and TLSVersMax bound the offered versions. They are usually
	// left zero and derived from the SupportedVersions extension.
	TLSVersMin uint16
	TLSVersMax uint16
}

// helloRenderer turns a ClientHelloSpec into both wire bytes and a populated
// *clientHelloMsg, keeping the two consistent. It also retains the private
// halves of generated key shares so the handshake can complete whichever group
// the server selects.
type helloRenderer struct {
	uconn *UConn
	hello *clientHelloMsg
	spec  *ClientHelloSpec

	greasePrimary     uint16                           // shared GREASE value for ciphers/groups/versions
	greaseExtSeq      int                              // counter for distinct per-extension GREASE
	renderedKeyShares []keyShare                       // what the key_share extension emits
	keyShareKeys      *keySharePrivateKeys             // primary, handed to crypto/tls
	extraKeyShareKeys map[CurveID]*keySharePrivateKeys // all offered groups
}

func newHelloRenderer(u *UConn, hello *clientHelloMsg, spec *ClientHelloSpec) *helloRenderer {
	return &helloRenderer{
		uconn:             u,
		hello:             hello,
		spec:              spec,
		greasePrimary:     drawGREASE(),
		extraKeyShareKeys: map[CurveID]*keySharePrivateKeys{},
	}
}

func (r *helloRenderer) randReader() io.Reader {
	if r.uconn != nil && r.uconn.config != nil {
		return r.uconn.config.rand()
	}
	return rand.Reader
}

// grease maps a GREASE placeholder to the hello's shared GREASE value and
// leaves every other value untouched.
func (r *helloRenderer) grease(v uint16) uint16 {
	if v == GREASEPlaceholder || isGREASEUint16(v) {
		return r.greasePrimary
	}
	return v
}

// nextGREASE returns a distinct valid GREASE value for a slot that needs its
// own (the two GREASE extensions, the GREASE key share).
func (r *helloRenderer) nextGREASE() uint16 {
	r.greaseExtSeq++
	// Derive a distinct nibble from the primary so values differ but stay
	// deterministic within one hello.
	nibble := byte((r.greasePrimary>>8)&0x0f) + byte(r.greaseExtSeq)*2
	nibble &= 0x0f
	v := uint16(nibble)<<12 | 0x0a00 | uint16(nibble)<<4 | 0x0a
	return v
}

func drawGREASE() uint16 {
	var b [1]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		b[0] = 0
	}
	nibble := uint16(b[0] & 0x0f)
	return nibble<<12 | 0x0a00 | nibble<<4 | 0x0a
}

// buildKeyShares generates (or passes through) the key shares for the
// key_share extension and records the private keys.
func (r *helloRenderer) buildKeyShares(e *KeyShareExtension) error {
	r.renderedKeyShares = r.renderedKeyShares[:0]
	logical := make([]keyShare, 0, len(e.KeyShares))
	primarySet := false
	for _, ks := range e.KeyShares {
		g := ks.Group
		if isGREASEUint16(uint16(g)) {
			data := ks.Data
			if len(data) == 0 {
				data = []byte{0}
			}
			r.renderedKeyShares = append(r.renderedKeyShares, keyShare{group: CurveID(r.nextGREASE()), data: data})
			continue
		}
		if len(ks.Data) > 0 {
			// Caller supplied explicit share bytes; we hold no private key, so
			// the server must not select this group. Still offered for shape.
			r.renderedKeyShares = append(r.renderedKeyShares, keyShare{group: g, data: ks.Data})
			logical = append(logical, keyShare{group: g, data: ks.Data})
			continue
		}
		ke, err := keyExchangeForCurveID(g)
		if err != nil {
			return err
		}
		priv, shares, err := ke.keyShares(r.randReader())
		if err != nil {
			return err
		}
		// shares[0] always matches g; any fallback share (shares[1]) belongs to
		// a separate spec entry, so emit only shares[0] here.
		r.renderedKeyShares = append(r.renderedKeyShares, shares[0])
		logical = append(logical, shares[0])
		r.extraKeyShareKeys[g] = priv
		if !primarySet {
			r.keyShareKeys = priv
			primarySet = true
		}
	}
	r.hello.keyShares = logical
	return nil
}

var errNoKeyShares = errors.New("utls: spec reached TLS 1.3 without a key_share")

// render produces the full ClientHello body bytes (the handshake message body,
// i.e. everything crypto/tls stores in clientHelloMsg.original, minus the
// 4-byte handshake header which writeHandshakeRecord adds). It is a two-pass
// process so a padding extension can target a final length.
func (r *helloRenderer) render() ([]byte, error) {
	// Pass 1: resolve padding to zero so we can measure the unpadded length.
	for _, ext := range r.spec.Extensions {
		if p, ok := ext.(*UtlsPaddingExtension); ok {
			p.WillPad = false
			p.PaddingLen = 0
		}
	}
	body, err := r.assemble()
	if err != nil {
		return nil, err
	}
	// Pass 2: if there is a padding extension, compute its length from the
	// unpadded size and re-assemble.
	for _, ext := range r.spec.Extensions {
		p, ok := ext.(*UtlsPaddingExtension)
		if !ok {
			continue
		}
		unpadded := len(body)
		if p.GetPaddingLen != nil {
			p.PaddingLen, p.WillPad = p.GetPaddingLen(unpadded)
		} else {
			p.PaddingLen, p.WillPad = BoringPaddingStyle(unpadded)
		}
		return r.assemble()
	}
	return body, nil
}

// assemble renders the ClientHello body once, from the current extension state.
func (r *helloRenderer) assemble() ([]byte, error) {
	h := r.hello
	// legacy_version is capped at TLS 1.2 (RFC 8446 Section 4.1.2).
	legacyVersion := h.vers
	if legacyVersion == 0 {
		legacyVersion = VersionTLS12
	}

	var exts []byte
	for _, ext := range r.spec.Extensions {
		b, err := ext.marshal(r)
		if err != nil {
			return nil, err
		}
		exts = append(exts, b...)
	}

	// ClientHello body: legacy_version(2) random(32) session_id cipher_suites
	// compression_methods extensions.
	out := make([]byte, 0, 2+32+1+len(h.sessionId)+2+2*len(r.spec.CipherSuites)+1+len(r.spec.CompressionMethods)+2+len(exts))
	out = append(out, byte(legacyVersion>>8), byte(legacyVersion))
	out = append(out, h.random...)
	out = append(out, byte(len(h.sessionId)))
	out = append(out, h.sessionId...)
	out = append(out, byte(len(r.spec.CipherSuites)*2>>8), byte(len(r.spec.CipherSuites)*2))
	for _, cs := range r.spec.CipherSuites {
		cs = r.grease(cs)
		out = append(out, byte(cs>>8), byte(cs))
	}
	out = append(out, byte(len(r.spec.CompressionMethods)))
	out = append(out, r.spec.CompressionMethods...)
	out = append(out, byte(len(exts)>>8), byte(len(exts)))
	out = append(out, exts...)

	// Prepend the handshake header: type (1) + uint24 length. crypto/tls stores
	// this full message (with header) in clientHelloMsg.original.
	msg := make([]byte, 4+len(out))
	msg[0] = typeClientHello
	msg[1] = byte(len(out) >> 16)
	msg[2] = byte(len(out) >> 8)
	msg[3] = byte(len(out))
	copy(msg[4:], out)
	return msg, nil
}

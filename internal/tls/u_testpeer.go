// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// A controllable TLS 1.3 server peer for tests and downstream adapters: the
// mirrored crypto/tls server plus the server side of certificate compression,
// ALPS and record_size_limit, which stock crypto/tls does not implement. It is
// reachable only through NewTestPeer (internal package); a Conn created by
// tls.Server has no hooks and is unaffected.

import (
	"bytes"
	"compress/zlib"
	"errors"
	"net"
	"slices"
	"sync"

	"github.com/klauspost/compress/zstd"
	brrr "github.com/molecule-man/go-brrr"
	"golang.org/x/crypto/cryptobyte"
)

// TestPeerOptions selects what the peer negotiates when the client offers it.
type TestPeerOptions struct {
	// CompressCertificate: algorithm to use if offered (0 = never compress).
	CompressCertificate CertCompressionAlgo
	// CorruptCompressed mutates the compressed payload (negative tests).
	CorruptCompressed func(*compressedCertificateMsg)
	// ALPSSettings: server ALPS settings per ALPN protocol.
	ALPSSettings map[string][]byte
	// RecordSizeLimit to send if the client offered record_size_limit (0 = none).
	RecordSizeLimit uint16
	// UnsolicitedRecordSizeLimit sends it even if not offered (negative tests).
	UnsolicitedRecordSizeLimit bool
	// HonorClientRecordSizeLimit caps the peer's outgoing records at the
	// client's advertised record_size_limit (otherwise it ignores it, which a
	// conforming client must reject with record_overflow).
	HonorClientRecordSizeLimit bool
}

// TestPeerResult reports what happened during the peer's handshake.
type TestPeerResult struct {
	mu                     sync.Mutex
	OfferedCompression     []CertCompressionAlgo
	CompressedWith         CertCompressionAlgo
	ALPSCodepoint          uint16
	ClientALPSSettings     []byte
	ClientALPSReceived     bool
	OfferedRecordSizeLimit uint16
	MaxRecordReceived      int
}

type uServerHooks struct {
	opts       TestPeerOptions
	res        *TestPeerResult
	clientEE   []byte
	writeLimit int
}

// NewTestPeer returns a server Conn with the test-peer hooks.
func NewTestPeer(conn net.Conn, config *Config, opts TestPeerOptions) (*Conn, *TestPeerResult) {
	c := Server(conn, config)
	res := &TestPeerResult{}
	c.userver = &uServerHooks{opts: opts, res: res}
	return c, res
}

// Snapshot returns a copy of the result safe to read after the handshake.
func (r *TestPeerResult) Snapshot() TestPeerResult {
	r.mu.Lock()
	defer r.mu.Unlock()
	return TestPeerResult{
		OfferedCompression: slices.Clone(r.OfferedCompression), CompressedWith: r.CompressedWith,
		ALPSCodepoint: r.ALPSCodepoint, ClientALPSSettings: slices.Clone(r.ClientALPSSettings),
		ClientALPSReceived: r.ClientALPSReceived, OfferedRecordSizeLimit: r.OfferedRecordSizeLimit,
		MaxRecordReceived: r.MaxRecordReceived,
	}
}

func (h *uServerHooks) observe(c *Conn, data []byte) error {
	if data[0] == typeEncryptedExtensions {
		h.clientEE = slices.Clone(data)
	}
	return nil
}

func (h *uServerHooks) clientExtensions(hs *serverHandshakeStateTLS13) map[uint16][]byte {
	out := map[uint16][]byte{}
	exts, err := extractRawExtensions(hs.clientHello)
	if err != nil {
		return out
	}
	for _, e := range exts {
		out[e.extType] = e.data
	}
	return out
}

// encryptedExtensions adds ALPS / record_size_limit to the server's EE.
func (h *uServerHooks) encryptedExtensions(hs *serverHandshakeStateTLS13, ee *encryptedExtensionsMsg) handshakeMessage {
	exts := h.clientExtensions(hs)
	var extra cryptobyte.Builder
	if lim, ok := exts[extensionRecordSizeLimit]; (ok && len(lim) == 2 && h.opts.RecordSizeLimit != 0) || h.opts.UnsolicitedRecordSizeLimit {
		if ok {
			h.res.mu.Lock()
			h.res.OfferedRecordSizeLimit = uint16(lim[0])<<8 | uint16(lim[1])
			h.res.mu.Unlock()
			if h.opts.HonorClientRecordSizeLimit {
				h.writeLimit = int(h.res.OfferedRecordSizeLimit) - 1 // TLS 1.3 content type
			}
		}
		v := h.opts.RecordSizeLimit
		if v == 0 {
			v = 512
		}
		extra.AddUint16(extensionRecordSizeLimit)
		extra.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(v) })
	}
	for _, cp := range []uint16{extensionApplicationSettings, extensionApplicationSettingsNew} {
		body, ok := exts[cp]
		if !ok || ee.alpnProtocol == "" {
			continue
		}
		settings, want := h.opts.ALPSSettings[ee.alpnProtocol]
		if !want {
			continue
		}
		s := cryptobyte.String(body)
		var list cryptobyte.String
		offered := false
		if s.ReadUint16LengthPrefixed(&list) {
			for !list.Empty() {
				var p cryptobyte.String
				if !list.ReadUint8LengthPrefixed(&p) {
					break
				}
				offered = offered || string(p) == ee.alpnProtocol
			}
		}
		if !offered {
			continue
		}
		h.res.mu.Lock()
		h.res.ALPSCodepoint = cp
		h.res.mu.Unlock()
		extra.AddUint16(cp)
		extra.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(settings) })
	}
	add, _ := extra.Bytes()
	if len(add) == 0 {
		return ee
	}
	return rawHandshake{func() ([]byte, error) {
		base, err := ee.marshal()
		if err != nil {
			return nil, err
		}
		// base = type(1) len(3) extlen(2) exts
		body := append(slices.Clone(base[6:]), add...)
		var b cryptobyte.Builder
		b.AddUint8(typeEncryptedExtensions)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(body) })
		})
		return b.Bytes()
	}}
}

type rawHandshake struct{ f func() ([]byte, error) }

func (r rawHandshake) marshal() ([]byte, error) { return r.f() }
func (r rawHandshake) unmarshal([]byte) bool    { return false }

// certificate optionally replaces the Certificate with a CompressedCertificate.
func (h *uServerHooks) certificate(hs *serverHandshakeStateTLS13, cert *certificateMsgTLS13) handshakeMessage {
	exts := h.clientExtensions(hs)
	body, ok := exts[extensionCompressCertificate]
	if !ok {
		return cert
	}
	s := cryptobyte.String(body)
	var list cryptobyte.String
	var offered []CertCompressionAlgo
	if s.ReadUint8LengthPrefixed(&list) {
		for !list.Empty() {
			var a uint16
			if !list.ReadUint16(&a) {
				break
			}
			offered = append(offered, CertCompressionAlgo(a))
		}
	}
	h.res.mu.Lock()
	h.res.OfferedCompression = offered
	h.res.mu.Unlock()
	alg := h.opts.CompressCertificate
	if alg == 0 || !slices.Contains(offered, alg) {
		return cert
	}
	raw, err := cert.marshal()
	if err != nil {
		return cert
	}
	payload := raw[4:]
	var buf bytes.Buffer
	switch alg {
	case CertCompressionZlib:
		w := zlib.NewWriter(&buf)
		w.Write(payload)
		w.Close()
	case CertCompressionBrotli:
		w, err := brrr.NewWriter(&buf, 5)
		if err != nil {
			return cert
		}
		w.Write(payload)
		w.Close()
	case CertCompressionZstd:
		w, _ := zstd.NewWriter(&buf)
		w.Write(payload)
		w.Close()
	default:
		return cert
	}
	m := &compressedCertificateMsg{algorithm: uint16(alg), uncompressedLength: uint32(len(payload)), compressed: buf.Bytes()}
	if h.opts.CorruptCompressed != nil {
		h.opts.CorruptCompressed(m)
	}
	h.res.mu.Lock()
	h.res.CompressedWith = alg
	h.res.mu.Unlock()
	return m
}

// readClientEncryptedExtensions reads the client's EncryptedExtensions when
// ALPS was negotiated.
func (h *uServerHooks) readClientEncryptedExtensions(hs *serverHandshakeStateTLS13) error {
	h.res.mu.Lock()
	cp := h.res.ALPSCodepoint
	h.res.mu.Unlock()
	if cp == 0 {
		return nil
	}
	c := hs.c
	if _, err := c.flush(); err != nil { // the client answers the server Finished
		return err
	}
	msg, err := c.readHandshake(hs.transcript)
	if err != nil {
		return err
	}
	if _, ok := msg.(*encryptedExtensionsMsg); !ok || h.clientEE == nil {
		c.sendAlert(alertUnexpectedMessage)
		return errors.New("test peer: expected client EncryptedExtensions with ALPS")
	}
	s := cryptobyte.String(h.clientEE[4:])
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		return errors.New("test peer: bad client EncryptedExtensions")
	}
	for !exts.Empty() {
		var id uint16
		var body cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&body) {
			return errors.New("test peer: bad client EncryptedExtensions")
		}
		if id == cp {
			h.res.mu.Lock()
			h.res.ClientALPSReceived = true
			h.res.ClientALPSSettings = slices.Clone([]byte(body))
			h.res.mu.Unlock()
		}
	}
	return nil
}

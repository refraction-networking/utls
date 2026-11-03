// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Negotiated behavior of fingerprint extensions that stock crypto/tls does not
// implement: certificate compression (RFC 8879), ALPS
// (draft-vvv-tls-alps) and record_size_limit (RFC 8449). Each is reached from
// a small [uTLS] hunk; everything here is inert unless the ClientHello offered
// the corresponding extension.

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/klauspost/compress/zstd"
	brrr "github.com/molecule-man/go-brrr"
	"golang.org/x/crypto/cryptobyte"
)

// maxDecompressedCertificate bounds CompressedCertificate.uncompressed_length.
// RFC 8879 allows up to 2^24-1; real chains (including ML-DSA) are far below
// 1 MiB, and a hard cap bounds decompression-bomb memory.
const maxDecompressedCertificate = 1 << 20

// compressedCertificateMsg is RFC 8879's CompressedCertificate.
type compressedCertificateMsg struct {
	algorithm          uint16
	uncompressedLength uint32
	compressed         []byte
}

func (m *compressedCertificateMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeCompressedCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16(m.algorithm)
		b.AddUint24(m.uncompressedLength)
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.compressed) })
	})
	return b.Bytes()
}

func (m *compressedCertificateMsg) unmarshal(data []byte) bool {
	*m = compressedCertificateMsg{}
	s := cryptobyte.String(data)
	var compressed cryptobyte.String
	if !s.Skip(4) || !s.ReadUint16(&m.algorithm) || !s.ReadUint24(&m.uncompressedLength) ||
		!s.ReadUint24LengthPrefixed(&compressed) || !s.Empty() || len(compressed) == 0 {
		return false
	}
	m.compressed = []byte(compressed)
	return true
}

// uCompressedCertificateMsg returns a message to parse a CompressedCertificate
// into, or nil if the client did not offer certificate compression (then the
// message is unexpected, as in stock crypto/tls).
func (c *Conn) uCompressedCertificateMsg() handshakeMessage {
	if c.uconn == nil || c.uconn.build == nil || len(c.uconn.build.certCompression) == 0 || c.vers != VersionTLS13 {
		return nil
	}
	return new(compressedCertificateMsg)
}

// uDecompressCertificate turns a CompressedCertificate (already added to the
// transcript as received, per RFC 8879) into the Certificate it carries.
func (c *Conn) uDecompressCertificate(msg any) (any, error) {
	m, ok := msg.(*compressedCertificateMsg)
	if !ok {
		return msg, nil
	}
	cert, err := decompressCertificate(m, c.uconn.build.certCompression)
	if err != nil {
		c.sendAlert(alertBadCertificate)
		return nil, err
	}
	return cert, nil
}

func decompressCertificate(m *compressedCertificateMsg, offered []CertCompressionAlgo) (*certificateMsgTLS13, error) {
	if !slices.Contains(offered, CertCompressionAlgo(m.algorithm)) {
		return nil, fmt.Errorf("tls: server used unoffered certificate compression algorithm %d", m.algorithm)
	}
	if m.uncompressedLength == 0 || m.uncompressedLength > maxDecompressedCertificate {
		return nil, fmt.Errorf("tls: compressed certificate uncompressed_length %d out of range", m.uncompressedLength)
	}
	compressed := bytes.NewReader(m.compressed)
	var r io.Reader
	switch CertCompressionAlgo(m.algorithm) {
	case CertCompressionZlib:
		zr, err := zlib.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("tls: compressed certificate: %w", err)
		}
		defer zr.Close()
		r = zr
	case CertCompressionBrotli:
		br := brrr.NewReader(compressed)
		defer br.Close()
		r = br
	case CertCompressionZstd:
		zr, err := zstd.NewReader(compressed, zstd.WithDecoderMaxMemory(maxDecompressedCertificate*2), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, fmt.Errorf("tls: compressed certificate: %w", err)
		}
		defer zr.Close()
		r = zr
	default:
		return nil, fmt.Errorf("tls: unsupported certificate compression algorithm %d", m.algorithm)
	}
	raw := make([]byte, 4+int(m.uncompressedLength))
	raw[0] = typeCertificate
	raw[1], raw[2], raw[3] = byte(m.uncompressedLength>>16), byte(m.uncompressedLength>>8), byte(m.uncompressedLength)
	if _, err := io.ReadFull(r, raw[4:]); err != nil {
		return nil, fmt.Errorf("tls: decompressed certificate shorter than uncompressed_length: %w", err)
	}
	// The stream must end exactly here (no excess output, no deferred decoder
	// error) and must consume the whole compressed payload (RFC 8879, Section 4).
	var extra [1]byte
	if n, err := io.ReadFull(r, extra[:]); n != 0 {
		return nil, errors.New("tls: decompressed certificate longer than uncompressed_length")
	} else if err != io.EOF {
		return nil, fmt.Errorf("tls: compressed certificate stream did not end cleanly: %v", err)
	}
	if compressed.Len() != 0 {
		return nil, errors.New("tls: trailing data after the compressed certificate stream")
	}
	cert := new(certificateMsgTLS13)
	if !cert.unmarshal(raw) {
		return nil, errors.New("tls: invalid Certificate message inside CompressedCertificate")
	}
	return cert, nil
}

// uObserveHandshake sees every handshake message the client parses. It reads
// the server's EncryptedExtensions for ALPS and record_size_limit, and the
// ServerHello (TLS 1.2) for record_size_limit, enforcing that the server only
// answers what was offered.
func (c *Conn) uObserveHandshake(data []byte) error {
	if c.userver != nil {
		return c.userver.observe(c, data)
	}
	u := c.uconn
	if u == nil || u.build == nil || len(data) < 4 {
		return nil
	}
	switch data[0] {
	case typeEncryptedExtensions:
		return c.uReadServerExtensions(data, true)
	case typeServerHello:
		return c.uReadServerExtensions(data, false)
	}
	return nil
}

func (c *Conn) uReadServerExtensions(data []byte, ee bool) error {
	u := c.uconn
	s := cryptobyte.String(data[4:])
	if !ee {
		var sid cryptobyte.String
		var suite uint16
		var comp uint8
		if !s.Skip(2+32) || !s.ReadUint8LengthPrefixed(&sid) || !s.ReadUint16(&suite) || !s.ReadUint8(&comp) {
			return nil // crypto/tls reports the decode error
		}
		if s.Empty() {
			return nil
		}
	}
	var exts cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&exts) {
		return nil
	}
	var alpn string
	var alpsBody []byte
	alpsSeen := false
	for !exts.Empty() {
		var id uint16
		var body cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&body) {
			return nil
		}
		switch id {
		case extensionALPN:
			var list, p cryptobyte.String
			if body.ReadUint16LengthPrefixed(&list) && list.ReadUint8LengthPrefixed(&p) {
				alpn = string(p)
			}
		case extensionRecordSizeLimit:
			if u.build.recordSizeLimit == 0 {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: server sent unsolicited record_size_limit")
			}
			var lim uint16
			if !body.ReadUint16(&lim) || !body.Empty() || lim < 64 {
				c.sendAlert(alertIllegalParameter)
				return errors.New("tls: invalid record_size_limit from server")
			}
			n := int(lim)
			if ee {
				n-- // TLS 1.3: the limit includes the inner content type byte
			}
			u.mu.Lock()
			u.peerRecordSizeLimit = min(n, maxPlaintext)
			u.recordLimitNegotiated = true
			u.mu.Unlock()
		case extensionApplicationSettings, extensionApplicationSettingsNew:
			if !ee || u.build.alps == nil || u.build.alps.ID() != id {
				c.sendAlert(alertUnsupportedExtension)
				return errors.New("tls: server sent unsolicited application_settings")
			}
			alpsSeen, alpsBody = true, slices.Clone([]byte(body))
		}
	}
	if alpsSeen {
		if alpn == "" || !slices.Contains(u.build.alps.protocols(u.hello), alpn) {
			c.sendAlert(alertIllegalParameter)
			return errors.New("tls: server negotiated ALPS for an ALPN protocol the client did not offer ALPS for")
		}
		u.mu.Lock()
		u.alpsNegotiated, u.peerALPS = true, alpsBody
		u.mu.Unlock()
	}
	return nil
}

// clientEncryptedExtensionsMsg is the client's EncryptedExtensions carrying
// its ALPS settings.
type clientEncryptedExtensionsMsg struct {
	codepoint uint16
	settings  []byte
}

func (m *clientEncryptedExtensionsMsg) marshal() ([]byte, error) {
	var b cryptobyte.Builder
	b.AddUint8(typeEncryptedExtensions)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
			b.AddUint16(m.codepoint)
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(m.settings) })
		})
	})
	return b.Bytes()
}

func (m *clientEncryptedExtensionsMsg) unmarshal([]byte) bool { return false }

// uSendClientEncryptedExtensions sends the client's ALPS settings after the
// server Finished when ALPS was negotiated.
func (hs *clientHandshakeStateTLS13) uSendClientEncryptedExtensions() error {
	c := hs.c
	u := c.uconn
	if u == nil || u.build == nil || !u.alpsNegotiated {
		return nil
	}
	msg := &clientEncryptedExtensionsMsg{codepoint: u.build.alps.ID(), settings: u.build.alps.Settings}
	_, err := c.writeHandshakeRecord(msg, hs.transcript)
	return err
}

// uLimitPayload applies the peer's record_size_limit to outgoing records.
func (c *Conn) uLimitPayload(n int) int {
	lim := 0
	if c.uconn != nil {
		c.uconn.mu.Lock()
		lim = c.uconn.peerRecordSizeLimit
		c.uconn.mu.Unlock()
	} else if c.userver != nil {
		lim = c.userver.writeLimit
	}
	if lim > 0 && lim < n {
		return lim
	}
	return n
}

// uRecordTooLarge enforces the client's own advertised record_size_limit on
// protected incoming records once the server acknowledged it (RFC 8449
// Section 4). Before decryption (ciphertextLen >= 0) it checks the exact TLS
// 1.3 inner plaintext length (content + type + padding); after decryption
// (plaintextLen >= 0) the TLS 1.2 plaintext length.
func (c *Conn) uRecordTooLarge(ciphertextLen, plaintextLen int) bool {
	u := c.uconn
	if u == nil || u.build == nil || u.build.recordSizeLimit == 0 || c.in.cipher == nil {
		return false
	}
	u.mu.Lock()
	ok := u.recordLimitNegotiated
	u.mu.Unlock()
	if !ok {
		return false
	}
	lim := int(u.build.recordSizeLimit)
	if ciphertextLen >= 0 {
		if c.vers != VersionTLS13 {
			return false
		}
		a, isAEAD := c.in.cipher.(aead)
		return isAEAD && ciphertextLen-a.Overhead() > lim
	}
	return c.vers != VersionTLS13 && plaintextLen > lim
}

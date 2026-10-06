// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"compress/zlib"
	"math/rand"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func TestDecompressCertZlibAndZstd(t *testing.T) {
	incompressibleCertificate := make([]byte, 256<<10)
	rand.New(rand.NewSource(0)).Read(incompressibleCertificate)
	for _, codec := range certificateTestCodecs {
		t.Run(codec.name, func(t *testing.T) {
			for _, test := range []struct {
				name        string
				certificate []byte
			}{
				{"small", []byte("test certificate")},
				{"large_compressible", bytes.Repeat([]byte("certificate"), 32<<10)},
				{"large_incompressible", incompressibleCertificate},
			} {
				t.Run(test.name, func(t *testing.T) {
					body := marshalCompressionTestCertificate(t, test.certificate)
					compressed := codec.compress(t, body)
					if test.name == "large_incompressible" && len(compressed) <= 128<<10 {
						t.Fatalf("compressed certificate is only %d bytes; want more than 128 KiB", len(compressed))
					}
					hs := compressionTestHandshake(codec.algorithm)
					got, err := hs.decompressCert(utlsCompressedCertificateMsg{
						algorithm:                    uint16(codec.algorithm),
						uncompressedLength:           uint32(len(body)),
						compressedCertificateMessage: compressed,
					})
					if err != nil {
						t.Fatal(err)
					}
					if got == nil || len(got.certificate.Certificate) != 1 || !bytes.Equal(got.certificate.Certificate[0], test.certificate) {
						t.Fatal("decompressed certificate differs from the original")
					}
					if len(hs.c.sendBuf) != 0 {
						t.Fatalf("sent an alert for a valid certificate: %x", hs.c.sendBuf)
					}
				})
			}
		})
	}
}

func TestDecompressCertZlibAndZstdRejectsInvalidMessages(t *testing.T) {
	body := marshalCompressionTestCertificate(t, []byte("test certificate"))
	for _, codec := range certificateTestCodecs {
		t.Run(codec.name, func(t *testing.T) {
			compressed := codec.compress(t, body)
			for _, test := range []struct {
				name       string
				compressed []byte
				length     uint32
			}{
				{"advertised_length_too_large", compressed, uint32(len(body) + 1)},
				{"advertised_length_too_small", compressed, uint32(len(body) - 1)},
				{"truncated_stream", compressed[:len(compressed)-1], uint32(len(body))},
				{"extra_decompressed_byte", codec.compress(t, append(bytes.Clone(body), 0)), uint32(len(body))},
				{"trailing_compressed_bytes", append(bytes.Clone(compressed), 0, 1), uint32(len(body))},
			} {
				t.Run(test.name, func(t *testing.T) {
					hs := compressionTestHandshake(codec.algorithm)
					got, err := hs.decompressCert(utlsCompressedCertificateMsg{
						algorithm:                    uint16(codec.algorithm),
						uncompressedLength:           test.length,
						compressedCertificateMessage: test.compressed,
					})
					if err == nil || got != nil {
						t.Fatal("accepted an invalid compressed certificate message")
					}
					alertRecord := hs.c.sendBuf
					if len(alertRecord) != recordHeaderLen+2 || alertRecord[0] != byte(recordTypeAlert) ||
						alertRecord[recordHeaderLen] != alertLevelError || alertRecord[recordHeaderLen+1] != byte(alertBadCertificate) {
						t.Fatalf("sent alert %x, want bad_certificate", alertRecord)
					}
				})
			}
		})
	}
}

var certificateTestCodecs = []struct {
	name      string
	algorithm CertCompressionAlgo
	compress  func(*testing.T, []byte) []byte
}{
	{"zlib", CertCompressionZlib, compressZlibTestCertificate},
	{"zstd", CertCompressionZstd, compressZstdTestCertificate},
}

func compressionTestHandshake(algorithm CertCompressionAlgo) *clientHandshakeStateTLS13 {
	return &clientHandshakeStateTLS13{
		c: &Conn{buffering: true, config: &Config{}},
		uconn: &UConn{
			certCompressionAlgs: []CertCompressionAlgo{algorithm},
		},
	}
}

func marshalCompressionTestCertificate(t *testing.T, certificate []byte) []byte {
	t.Helper()
	original, err := (&certificateMsgTLS13{certificate: Certificate{
		Certificate: [][]byte{certificate},
	}}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	return original[4:]
}

func compressZlibTestCertificate(t *testing.T, body []byte) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w := zlib.NewWriter(&compressed)
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func compressZstdTestCertificate(t *testing.T, body []byte) []byte {
	t.Helper()
	w, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	return w.EncodeAll(body, nil)
}

// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"math/rand"
	"testing"

	"github.com/molecule-man/go-brrr"
)

func TestDecompressCertBrotli(t *testing.T) {
	randomCertificate := make([]byte, 64<<10)
	rand.New(rand.NewSource(0)).Read(randomCertificate)
	for _, test := range []struct {
		name        string
		certificate []byte
		window      int
	}{
		{"small", []byte("test certificate"), 0},
		{"multiple_1KiB_windows", bytes.Repeat([]byte("certificate"), 1024), 10},
		{"multiple_4KiB_windows", bytes.Repeat([]byte("certificate"), 1024), 12},
		{"multiple_input_buffers", randomCertificate, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := marshalBrotliTestCertificate(t, test.certificate)
			compressed := compressBrotliTestCertificate(t, body, test.window)
			if test.name == "multiple_input_buffers" && len(compressed) <= 32<<10 {
				t.Fatalf("compressed certificate is only %d bytes; want more than 32 KiB", len(compressed))
			}
			got, err := brotliTestHandshake().decompressCert(utlsCompressedCertificateMsg{
				algorithm:                    uint16(CertCompressionBrotli),
				uncompressedLength:           uint32(len(body)),
				compressedCertificateMessage: compressed,
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(got.certificate.Certificate) != 1 || !bytes.Equal(got.certificate.Certificate[0], test.certificate) {
				t.Fatal("decompressed certificate differs from the original")
			}
		})
	}
}

func TestDecompressCertBrotliRejectsInvalidMessages(t *testing.T) {
	body := marshalBrotliTestCertificate(t, []byte("test certificate"))
	compressed := compressBrotliTestCertificate(t, body, 0)
	for _, test := range []struct {
		name       string
		compressed []byte
		length     uint32
	}{
		{"trailing_compressed_bytes", append(bytes.Clone(compressed), 0, 1), uint32(len(body))},
		{"extra_decompressed_byte", compressBrotliTestCertificate(t, append(bytes.Clone(body), 0), 0), uint32(len(body))},
		{"truncated_stream", compressed[:len(compressed)-1], uint32(len(body))},
		{"advertised_length_too_large", compressed, uint32(len(body) + 1)},
		{"advertised_length_too_small", compressed, uint32(len(body) - 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			hs := brotliTestHandshake()
			_, err := hs.decompressCert(utlsCompressedCertificateMsg{
				algorithm:                    uint16(CertCompressionBrotli),
				uncompressedLength:           test.length,
				compressedCertificateMessage: test.compressed,
			})
			if err == nil {
				t.Fatal("accepted an invalid compressed certificate message")
			}
			if len(hs.c.sendBuf) < 2 || hs.c.sendBuf[len(hs.c.sendBuf)-1] != byte(alertBadCertificate) {
				t.Fatalf("sent alert %x, want bad_certificate", hs.c.sendBuf)
			}
		})
	}
}

func brotliTestHandshake() *clientHandshakeStateTLS13 {
	return &clientHandshakeStateTLS13{
		c: &Conn{buffering: true, config: &Config{}},
		uconn: &UConn{
			certCompressionAlgs: []CertCompressionAlgo{CertCompressionBrotli},
		},
	}
}

func marshalBrotliTestCertificate(t *testing.T, certificate []byte) []byte {
	t.Helper()
	original, err := (&certificateMsgTLS13{certificate: Certificate{
		Certificate: [][]byte{certificate},
	}}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	return original[4:]
}

func compressBrotliTestCertificate(t *testing.T, body []byte, window int) []byte {
	t.Helper()
	var compressed bytes.Buffer
	w, err := brrr.NewWriterOptions(&compressed, 5, brrr.WriterOptions{LGWin: window})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

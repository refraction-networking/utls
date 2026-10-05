// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"testing"

	"github.com/molecule-man/go-brrr"
)

func TestDecompressCertBrotli(t *testing.T) {
	original, err := (&certificateMsgTLS13{certificate: Certificate{
		Certificate: [][]byte{[]byte("test certificate")},
	}}).marshal()
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := brrr.Compress(original[4:], 5)
	if err != nil {
		t.Fatal(err)
	}

	hs := &clientHandshakeStateTLS13{uconn: &UConn{
		certCompressionAlgs: []CertCompressionAlgo{CertCompressionBrotli},
	}}
	got, err := hs.decompressCert(utlsCompressedCertificateMsg{
		algorithm:                    uint16(CertCompressionBrotli),
		uncompressedLength:           uint32(len(original) - 4),
		compressedCertificateMessage: compressed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.certificate.Certificate) != 1 || string(got.certificate.Certificate[0]) != "test certificate" {
		t.Fatalf("got %#v, want test certificate", got.certificate.Certificate)
	}
}

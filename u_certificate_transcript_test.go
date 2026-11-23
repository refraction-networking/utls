// Copyright 2026 uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/cryptobyte"
)

type certificateTestExtension struct {
	extType uint16
	data    []byte
}

type certificateTestEntry struct {
	certificate []byte
	extensions  []certificateTestExtension
}

func ocspTestExtension(response []byte) certificateTestExtension {
	var b cryptobyte.Builder
	b.AddUint8(statusTypeOCSP)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(response) })
	return certificateTestExtension{extensionStatusRequest, b.BytesOrPanic()}
}

func sctTestExtension(scts ...[]byte) certificateTestExtension {
	var b cryptobyte.Builder
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		for _, sct := range scts {
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(sct) })
		}
	})
	return certificateTestExtension{extensionSCT, b.BytesOrPanic()}
}

// certificateTestMessage encodes a TLS 1.3 Certificate message with the
// extensions in the given order, as a server would put it on the wire.
func certificateTestMessage(entries ...certificateTestEntry) []byte {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // certificate_request_context
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			for _, entry := range entries {
				b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(entry.certificate) })
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					for _, ext := range entry.extensions {
						b.AddUint16(ext.extType)
						b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(ext.data) })
					}
				})
			}
		})
	})
	return b.BytesOrPanic()
}

// The server signs CertificateVerify over the Certificate message it sent, so
// the client transcript must hash those bytes. The cases are messages that
// marshal cannot reproduce: it writes the leaf's OCSP staple before its SCTs
// and drops every other extension. Some servers in production send SCTs first.
func TestCertificateMsgTLS13TranscriptUsesWireBytes(t *testing.T) {
	leaf := []byte("leaf certificate")
	intermediate := []byte("intermediate certificate")
	ocsp := ocspTestExtension([]byte("ocsp response"))
	sct := sctTestExtension([]byte("first sct"), []byte("second sct"))
	unknown := certificateTestExtension{0xff01, []byte("unknown")}

	for _, tc := range []struct {
		name    string
		entries []certificateTestEntry
	}{
		{"SCTs before the OCSP staple", []certificateTestEntry{
			{leaf, []certificateTestExtension{sct, ocsp}},
			{intermediate, nil},
		}},
		{"unknown extension on the leaf", []certificateTestEntry{
			{leaf, []certificateTestExtension{ocsp, unknown}},
		}},
		{"extension on an intermediate", []certificateTestEntry{
			{leaf, []certificateTestExtension{ocsp}},
			{intermediate, []certificateTestExtension{sct}},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wire := certificateTestMessage(tc.entries...)
			var m certificateMsgTLS13
			if !m.unmarshal(wire) {
				t.Fatalf("unmarshal failed for %x", wire)
			}

			transcript := sha256.New()
			if err := transcriptMsg(&m, transcript); err != nil {
				t.Fatal(err)
			}
			want := sha256.Sum256(wire)
			if got := transcript.Sum(nil); !bytes.Equal(got, want[:]) {
				t.Errorf("transcript hash %x, want the hash of the wire bytes %x", got, want)
			}
		})
	}
}

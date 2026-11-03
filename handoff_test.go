// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// rec13 is a minimal TLS 1.3 record protector built only from a handed-off
// RecordLayerState, standing in for kTLS or a custom record layer.
type rec13 struct {
	aead cipher.AEAD
	iv   []byte
	seq  uint64
}

func newRec13(t *testing.T, suite uint16, key, iv []byte, seq uint64) *rec13 {
	t.Helper()
	var a cipher.AEAD
	var err error
	switch suite {
	case tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384:
		var b cipher.Block
		if b, err = aes.NewCipher(key); err == nil {
			a, err = cipher.NewGCM(b)
		}
	case tls.TLS_CHACHA20_POLY1305_SHA256:
		a, err = chacha20poly1305.New(key)
	default:
		t.Fatalf("suite %x", suite)
	}
	if err != nil {
		t.Fatal(err)
	}
	return &rec13{a, bytes.Clone(iv), seq}
}

func (r *rec13) nonce() []byte {
	n := bytes.Clone(r.iv)
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], r.seq)
	for i := range s {
		n[len(n)-8+i] ^= s[i]
	}
	r.seq++
	return n
}

func (r *rec13) seal(typ byte, data []byte) []byte {
	inner := append(bytes.Clone(data), typ)
	n := len(inner) + r.aead.Overhead()
	hdr := []byte{23, 3, 3, byte(n >> 8), byte(n)}
	return r.aead.Seal(hdr, r.nonce(), inner, hdr)
}

// open decrypts one record from b, returning content type, data, rest.
func (r *rec13) open(b []byte) (byte, []byte, []byte, error) {
	if len(b) < 5 {
		return 0, nil, b, io.ErrUnexpectedEOF
	}
	n := 5 + (int(b[3])<<8 | int(b[4]))
	if len(b) < n {
		return 0, nil, b, io.ErrUnexpectedEOF
	}
	pt, err := r.aead.Open(nil, r.nonce(), b[5:n], b[:5])
	if err != nil {
		return 0, nil, nil, err
	}
	i := len(pt) - 1
	for i >= 0 && pt[i] == 0 {
		i--
	}
	if i < 0 {
		return 0, nil, nil, errors.New("no content type")
	}
	return pt[i], pt[:i], b[n:], nil
}

func TestHandOffTLS13(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serr := make(chan error, 1)
	go func() {
		serr <- func() error {
			c, err := ln.Accept()
			if err != nil {
				return err
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			s := tls.Server(c, serverConfig(t))
			if _, err := s.Write([]byte("0123456789")); err != nil {
				return err
			}
			if _, err := s.Write([]byte("second")); err != nil {
				return err
			}
			b := make([]byte, 4)
			if _, err := io.ReadFull(s, b); err != nil || string(b) != "ping" {
				return errors.New("server got " + string(b) + ": " + errString(err))
			}
			// Exercise a KeyUpdate-free reply after the client's handed-off write.
			_, err = s.Write([]byte("pong"))
			return err
		}()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	rec := &recConn{Conn: raw}
	uc := UClient(rec, clientConfig(t), HelloChrome_Auto)
	if _, err := uc.HandOff(); err == nil {
		t.Fatal("HandOff before the handshake accepted")
	}
	b := make([]byte, 4)
	if _, err := io.ReadFull(uc, b); err != nil || string(b) != "0123" {
		t.Fatalf("read %q %v", b, err)
	}
	st, err := uc.HandOff()
	if err != nil {
		t.Fatal(err)
	}
	if st.Version != tls.VersionTLS13 || st.Conn != rec || st.WriteSeq == 0 && st.ReadSeq == 0 {
		t.Fatalf("state %+v", st)
	}
	if string(st.Plaintext) != "456789" {
		t.Fatalf("Plaintext %q", st.Plaintext)
	}
	sentAtHandOff := len(rec.written())
	if _, err := uc.Write([]byte("x")); !errors.Is(err, ErrHandedOff) {
		t.Fatalf("Write after HandOff: %v", err)
	}
	if _, err := uc.Read(b); !errors.Is(err, ErrHandedOff) {
		t.Fatalf("Read after HandOff: %v", err)
	}
	if _, err := uc.HandOff(); err == nil {
		t.Fatal("second HandOff accepted")
	}

	w := newRec13(t, st.CipherSuite, st.WriteKey, st.WriteIV, st.WriteSeq)
	if _, err := st.Conn.Write(w.seal(23, []byte("ping"))); err != nil {
		t.Fatal(err)
	}
	r := newRec13(t, st.CipherSuite, st.ReadKey, st.ReadIV, st.ReadSeq)
	buf := bytes.Clone(st.RawInput)
	var app []byte
	for !bytes.Contains(app, []byte("pong")) {
		typ, data, rest, err := r.open(buf)
		if err == io.ErrUnexpectedEOF {
			more := make([]byte, 4096)
			n, err := st.Conn.Read(more)
			if err != nil {
				t.Fatalf("raw read: %v (app so far %q)", err, app)
			}
			buf = append(buf, more[:n]...)
			continue
		}
		if err != nil {
			t.Fatalf("decrypt with handed-off keys: %v", err)
		}
		if typ == 23 {
			app = append(app, data...)
		} // 22: NewSessionTicket the client had not read yet
		buf = rest
	}
	if string(app) != "secondpong" {
		t.Fatalf("app data %q", app)
	}
	if err := <-serr; err != nil {
		t.Fatal(err)
	}
	// Close sends nothing (no close_notify under stale keys).
	before := len(rec.written())
	uc.Close()
	if after := len(rec.written()); after != before || before <= sentAtHandOff {
		t.Fatalf("written: at handoff %d, before close %d, after close %d", sentAtHandOff, before, after)
	}
}

func TestHandOffRejectsTLS12(t *testing.T) {
	scfg := serverConfig(t)
	scfg.MaxVersion = tls.VersionTLS12
	r := handshakeStd(t, HelloChrome_Auto, clientConfig(t), scfg, nil)
	r.ok(t)
	if _, err := r.uc.HandOff(); err == nil {
		t.Fatal("TLS 1.2 HandOff accepted")
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

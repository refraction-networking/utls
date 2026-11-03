// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"testing"
)

// exportBoth calls the native and the standard-state exporter, turning a
// panic into a test failure.
func exportBoth(t *testing.T, uc *UConn) (native, std []byte, nerr, serr error) {
	t.Helper()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("native exporter panicked: %v", r)
			}
		}()
		native, nerr = uc.ExportKeyingMaterial("EXPORTER-test", []byte("ctx"), 32)
	}()
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("standard exporter panicked: %v", r)
			}
		}()
		cs := uc.ConnectionState()
		std, serr = cs.ExportKeyingMaterial("EXPORTER-test", []byte("ctx"), 32)
	}()
	return
}

func TestExporterStates(t *testing.T) {
	// Before the handshake: both report the exporter is unavailable.
	c1, c2 := net.Pipe()
	defer c2.Close()
	uc := UClient(c1, clientConfig(t), HelloChrome_Auto)
	if _, _, nerr, serr := exportBoth(t, uc); !errors.Is(nerr, ErrExporterUnavailable) || serr == nil {
		t.Fatalf("before handshake: native %v, std %v", nerr, serr)
	}
	c1.Close()

	// TLS 1.3 handshake that fails certificate verification after ServerHello.
	ccfg := clientConfig(t)
	ccfg.RootCAs = x509.NewCertPool() // trusts nothing
	r := handshakeStd(t, HelloChrome_Auto, ccfg, serverConfig(t), nil)
	var cv *tls.CertificateVerificationError
	if !errors.As(r.cerr, &cv) {
		t.Fatalf("expected a verification failure, got %v", r.cerr)
	}
	if r.uc.ServerHelloRaw() == nil {
		t.Fatal("failure did not happen after ServerHello")
	}
	if _, _, nerr, serr := exportBoth(t, r.uc); !errors.Is(nerr, ErrExporterUnavailable) || serr == nil {
		t.Fatalf("after failed TLS 1.3 handshake: native %v, std %v", nerr, serr)
	}

	// Success (TLS 1.3 and TLS 1.2 with EMS), then Close: material is stable and
	// equal to the server's; it stays available after Close, as in crypto/tls.
	for _, max := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		scfg := serverConfig(t)
		scfg.MaxVersion = max
		r := handshakeStd(t, HelloChrome_Auto, clientConfig(t), scfg, nil)
		r.ok(t)
		native, std, nerr, serr := exportBoth(t, r.uc)
		if nerr != nil || serr != nil || !bytes.Equal(native, std) || len(native) != 32 {
			t.Fatalf("after success (%x): %v %v", max, nerr, serr)
		}
		want, err := r.sstate.ExportKeyingMaterial("EXPORTER-test", []byte("ctx"), 32)
		if err != nil || !bytes.Equal(want, native) {
			t.Fatalf("client and server keying material differ (%v)", err)
		}
		r.uc.Close()
		after, afterStd, nerr, serr := exportBoth(t, r.uc)
		if nerr != nil || serr != nil || !bytes.Equal(after, native) || !bytes.Equal(afterStd, native) {
			t.Fatalf("after Close: %v %v", nerr, serr)
		}
	}
}

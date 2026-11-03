// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"

	itls "github.com/refraction-networking/utls/v2/internal/tls"
)

// The field inventory (config_fields_test.go) only proves every field was
// considered; these tests check that converted fields BEHAVE as in crypto/tls.

func TestStdBridgeLayout(t *testing.T) {
	// Fails on a Go release that renames/retypes the two unexported fields the
	// bridge sets (internal/tls/u_stdcompat.go). Fix the bridge before release.
	ekm, ctx := itls.StdBridgeStatus()
	if !ekm || !ctx {
		t.Fatalf("crypto/tls layout changed: exporter=%v context=%v", ekm, ctx)
	}
}

// Simulated unsupported layouts take the documented safe paths.
func TestStdBridgeFallbacks(t *testing.T) {
	restore := itls.SetStdBridgeForTest(false, false)
	defer restore()
	r := handshakeStd(t, HelloChrome_Auto, clientConfig(t), serverConfig(t), nil)
	r.ok(t)
	cs := r.uc.ConnectionState()
	if _, err := cs.ExportKeyingMaterial("x", nil, 8); err == nil {
		t.Fatal("fallback exporter returned material")
	}
	if _, err := r.uc.ExportKeyingMaterial("x", nil, 8); err != nil {
		t.Fatalf("native exporter: %v", err)
	}
	var zero tls.ConnectionState
	_ = zero
	ccfg := clientConfig(t)
	ccfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return nil, nil }
	r = handshakeStd(t, HelloChrome_Auto, ccfg, serverConfig(t), nil)
	if r.cerr == nil || len(r.rec.written()) != 0 {
		t.Fatalf("GetClientCertificate without context bridge: err=%v written=%d", r.cerr, len(r.rec.written()))
	}
}

func TestExporter(t *testing.T) {
	for _, max := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		scfg := serverConfig(t)
		scfg.MaxVersion = max
		var verifyErr error
		ccfg := clientConfig(t)
		ccfg.VerifyConnection = func(cs tls.ConnectionState) error {
			// As in crypto/tls, the exporter is not available before the
			// handshake completes; uTLS reports that instead of panicking.
			_, verifyErr = cs.ExportKeyingMaterial("EXPORTER-test", nil, 32)
			return nil
		}
		r := handshakeStd(t, HelloChrome_Auto, ccfg, scfg, nil)
		r.ok(t)
		want, err := r.sstate.ExportKeyingMaterial("EXPORTER-test", nil, 32)
		if err != nil {
			t.Fatal(err)
		}
		a, err1 := r.uc.ExportKeyingMaterial("EXPORTER-test", nil, 32)
		cs := r.uc.ConnectionState()
		b, err2 := cs.ExportKeyingMaterial("EXPORTER-test", nil, 32)
		if err1 != nil || err2 != nil || !bytes.Equal(a, want) || !bytes.Equal(b, want) {
			t.Fatalf("%x: exporter mismatch: %v %v", max, err1, err2)
		}
		if max == tls.VersionTLS13 && !errors.Is(verifyErr, ErrExporterUnavailable) {
			t.Fatalf("exporter during VerifyConnection: %v", verifyErr)
		}
	}
	// A pre-handshake state never panics.
	c1, _ := net.Pipe()
	pre := UClient(c1, clientConfig(t), HelloChrome_Auto).ConnectionState()
	if _, err := pre.ExportKeyingMaterial("x", nil, 1); err == nil {
		t.Fatalf("pre-handshake exporter: %v", err)
	}
}

type ctxKey struct{}

func TestClientCertificateContext(t *testing.T) {
	scfg := serverConfig(t)
	scfg.ClientAuth = tls.RequireAnyClientCert
	var got any
	ccfg := clientConfig(t)
	ccfg.GetClientCertificate = func(cri *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		got = cri.Context().Value(ctxKey{})
		c := getPKI(t).cert
		return &c, nil
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			s := tls.Server(c, scfg)
			s.Handshake()
			s.Close()
		}
	}()
	raw, _ := net.Dial("tcp", ln.Addr().String())
	uc := UClient(raw, ccfg, HelloChrome_Auto)
	ctx := context.WithValue(context.Background(), ctxKey{}, "marker")
	if err := uc.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	uc.Close()
	if got != "marker" {
		t.Fatalf("CertificateRequestInfo.Context() value = %v", got)
	}
}

// A uTLS client and a crypto/tls client can share one standard session cache.
func TestSessionCacheSharedWithStdlib(t *testing.T) {
	for _, max := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		cache := tls.NewLRUClientSessionCache(8)
		scfg := serverConfig(t)
		scfg.MaxVersion = max
		ccfg := clientConfig(t)
		ccfg.ClientSessionCache = cache
		r := handshakeStd(t, HelloChrome_Auto, ccfg, scfg, nil)
		r.ok(t)
		r = handshakeStd(t, HelloChrome_Auto, ccfg, scfg, nil)
		r.ok(t)
		if !r.uc.ConnectionState().DidResume {
			t.Fatalf("%x: uTLS did not resume its own session", max)
		}
		// The ticket the uTLS client stored must be usable by crypto/tls.
		ln, _ := net.Listen("tcp", "127.0.0.1:0")
		go func() {
			c, err := ln.Accept()
			if err == nil {
				s := tls.Server(c, scfg)
				s.Handshake()
				io.Copy(io.Discard, s)
				s.Close()
			}
		}()
		raw, _ := net.Dial("tcp", ln.Addr().String())
		std := tls.Client(raw, ccfg)
		if err := std.Handshake(); err != nil {
			t.Fatal(err)
		}
		if !std.ConnectionState().DidResume {
			t.Fatalf("%x: crypto/tls could not resume the uTLS session", max)
		}
		std.Close()
		ln.Close()
	}
}

func TestSetSessionAndNewClientSession(t *testing.T) {
	cache := tls.NewLRUClientSessionCache(8)
	scfg := serverConfig(t)
	ccfg := clientConfig(t)
	ccfg.ClientSessionCache = cache
	handshakeStd(t, HelloChrome_Auto, ccfg, scfg, nil).ok(t)
	cs, ok := cache.Get("utls.test")
	if !ok {
		t.Fatal("no session")
	}
	// Inject it explicitly into a connection without a cache.
	r := handshakeStd(t, HelloFirefox_Auto, clientConfig(t), scfg, func(uc *UConn) {
		if err := uc.SetSession(cs); err != nil {
			t.Fatal(err)
		}
	})
	r.ok(t)
	if !r.uc.ConnectionState().DidResume {
		t.Fatal("SetSession did not resume")
	}
	// SetSessionParams validates its parameters.
	c1, _ := net.Pipe()
	if err := UClient(c1, clientConfig(t), HelloChrome_Auto).SetSessionParams(ClientSessionParams{Version: VersionTLS12, CipherSuite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, Secret: make([]byte, 47), Ticket: []byte{1}}); err == nil {
		t.Fatal("short master secret accepted")
	}
	// A forged ticket the server cannot decrypt falls back to a full handshake.
	scfg12 := serverConfig(t)
	scfg12.MaxVersion = tls.VersionTLS12
	r = handshakeStd(t, HelloChrome_Auto, clientConfig(t), scfg12, func(uc *UConn) {
		if err := uc.SetSessionParams(ClientSessionParams{Version: VersionTLS12, CipherSuite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, Secret: make([]byte, 48), Ticket: []byte("ticket")}); err != nil {
			t.Fatal(err)
		}
	})
	r.ok(t)
	if r.uc.ConnectionState().DidResume {
		t.Fatal("resumed an unknown ticket")
	}
	if !bytes.Contains(r.rec.firstRecord(), []byte("ticket")) {
		t.Fatal("injected TLS 1.2 ticket not sent")
	}
}

func echPair(t *testing.T) (list []byte, keys []tls.EncryptedClientHelloKey) {
	k, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(0xfe0d)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(3)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(k.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	cfg := b.BytesOrPanic()
	lb := cryptobyte.NewBuilder(nil)
	lb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(cfg) })
	return lb.BytesOrPanic(), []tls.EncryptedClientHelloKey{{Config: cfg, PrivateKey: k.Bytes(), SendAsRetry: true}}
}

func TestECHWithStdlibServer(t *testing.T) {
	list, keys := echPair(t)
	scfg := serverConfig(t)
	scfg.MinVersion = tls.VersionTLS13
	scfg.EncryptedClientHelloKeys = keys
	for _, id := range []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto, HelloSafari_Auto} {
		ccfg := clientConfig(t)
		ccfg.ServerName = "secret.example"
		ccfg.MinVersion = tls.VersionTLS13
		ccfg.EncryptedClientHelloConfigList = list
		r := handshakeStd(t, id, ccfg, scfg, nil)
		r.ok(t)
		if !r.uc.ConnectionState().ECHAccepted || !r.sstate.ECHAccepted {
			t.Fatalf("%s: ECH not accepted", id.Str())
		}
		if bytes.Contains(r.rec.written(), []byte("secret.example")) {
			t.Fatalf("%s: private name in clear", id.Str())
		}
	}
	// Rejection: the rejection verifier sees the outer certificate; the private
	// name is never sent.
	_, otherKeys := echPair(t)
	scfg.EncryptedClientHelloKeys = otherKeys
	ccfg := clientConfig(t)
	ccfg.ServerName = "secret.example"
	ccfg.MinVersion = tls.VersionTLS13
	ccfg.EncryptedClientHelloConfigList = list
	// crypto/tls (Go 1.27.3) calls the verifier before recording peer
	// certificates; uTLS mirrors that exactly.
	called := false
	ccfg.EncryptedClientHelloRejectionVerify = func(cs tls.ConnectionState) error {
		called = true
		return nil
	}
	r := handshakeStd(t, HelloChrome_Auto, ccfg, scfg, nil)
	var rej *tls.ECHRejectionError
	if !called || !errors.As(r.cerr, &rej) {
		t.Fatalf("rejection: err=%v called=%v", r.cerr, called)
	}
	if bytes.Contains(r.rec.written(), []byte("secret.example")) {
		t.Fatal("private name in clear after rejection")
	}
	// Hook + ECH fails before anything is sent.
	r = handshakeStd(t, HelloChrome_Auto, ccfg, scfg, func(uc *UConn) {
		if err := uc.SetClientHelloHook(func(*ClientHelloContext) error { return nil }); err != nil {
			t.Fatal(err)
		}
	})
	if !errors.Is(r.cerr, ErrHookWithECH) || len(r.rec.written()) != 0 {
		t.Fatalf("hook+ECH: %v", r.cerr)
	}
}

func TestConfigIsCopied(t *testing.T) {
	ccfg := clientConfig(t)
	c1, c2 := net.Pipe()
	defer c2.Close()
	uc := UClient(c1, ccfg, HelloChrome_Auto)
	ccfg.ServerName = "changed.example"
	if got := reflect.ValueOf(uc.u.Conn).Elem().FieldByName("config").Elem().FieldByName("ServerName").String(); got != "utls.test" {
		t.Fatalf("config not copied: %q", got)
	}
	_ = time.Second
}

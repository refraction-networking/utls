// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"
)

func allPresets() []ClientHelloID {
	return []ClientHelloID{HelloChrome_Auto, HelloChrome_155, HelloEdge_Auto, HelloFirefox_148, HelloFirefox_Auto, HelloSafari_Auto,
		HelloIOS_Auto, HelloAndroid_11_OkHttp, HelloQQ_Auto, HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN, HelloGolang}
}

func TestPresetsInterop(t *testing.T) {
	for _, id := range allPresets() {
		for _, max := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
			t.Run(id.Str()+"/"+map[uint16]string{tls.VersionTLS13: "tls13", tls.VersionTLS12: "tls12"}[max], func(t *testing.T) {
				scfg := serverConfig(t)
				scfg.MaxVersion = max
				r := handshakeStd(t, id, clientConfig(t), scfg, nil)
				r.ok(t)
				st := r.uc.ConnectionState()
				if !st.HandshakeComplete || len(st.PeerCertificates) == 0 {
					t.Fatal("incomplete state")
				}
			})
		}
	}
}

func TestPresetsHelloRetryRequest(t *testing.T) {
	for _, id := range allPresets() {
		spec, _ := id.Spec()
		if id == HelloAndroid_11_OkHttp || (spec != nil && !hasExtension(spec, 51)) {
			continue // TLS 1.2-only fingerprints
		}
		t.Run(id.Str(), func(t *testing.T) {
			scfg := serverConfig(t)
			scfg.CurvePreferences = []tls.CurveID{tls.CurveP384}
			r := handshakeStd(t, id, clientConfig(t), scfg, nil)
			r.ok(t)
			if !r.uc.ConnectionState().HelloRetryRequest {
				t.Skip("server did not need HelloRetryRequest (P-384 share offered)")
			}
		})
	}
}

func TestNoSilentFallback(t *testing.T) {
	for name, id := range map[string]ClientHelloID{"custom": HelloCustom, "zero": {}, "foreign": {Client: "Chrome", Version: "999"}} {
		c1, c2 := net.Pipe()
		rec := &recConn{Conn: c1}
		go func() { b := make([]byte, 1); c2.Read(b); c2.Close() }()
		uc := UClient(rec, clientConfig(t), id)
		err := uc.Handshake()
		if err == nil || len(rec.written()) != 0 {
			t.Fatalf("%s: err=%v written=%d", name, err, len(rec.written()))
		}
		if name != "foreign" && !errors.Is(err, ErrNoSpec) {
			t.Fatalf("%s: err=%v, want ErrNoSpec", name, err)
		}
		c1.Close()
	}
	bad := CustomFingerprint("Broken", "1", func() (*ClientHelloSpec, error) { return nil, errors.New("boom") })
	c1, _ := net.Pipe()
	if err := UClient(c1, clientConfig(t), bad).Handshake(); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("factory error not reported: %v", err)
	}
}

func TestApplyPreset(t *testing.T) {
	spec, _ := HelloFirefox_Auto.Spec()
	r := handshakeStd(t, HelloCustom, clientConfig(t), serverConfig(t), func(uc *UConn) {
		if err := uc.ApplyPreset(spec); err != nil {
			t.Fatal(err)
		}
	})
	r.ok(t)
	if err := r.uc.ApplyPreset(spec); err == nil {
		t.Fatal("ApplyPreset after the handshake was accepted")
	}
	if err := UClient(nil, nil, HelloCustom).ApplyPreset(&ClientHelloSpec{}); err == nil {
		t.Fatal("invalid spec accepted")
	}
}

func TestSpecsAreFresh(t *testing.T) {
	a, _ := HelloChrome_Auto.Spec()
	b, _ := HelloChrome_Auto.Spec()
	for i := range a.Extensions {
		for j := range b.Extensions {
			// Zero-size structs may share an address; only stateful ones matter.
			if reflect.TypeOf(a.Extensions[i]).Elem().Size() > 0 && a.Extensions[i] == b.Extensions[j] {
				t.Fatal("presets share extension objects")
			}
		}
	}
}

func TestParseFingerprint(t *testing.T) {
	for name, want := range map[string]ClientHelloID{
		"": HelloChrome_Auto, "chrome": HelloChrome_Auto, "Chrome-155": HelloChrome_155, "FIREFOX": HelloFirefox_Auto,
		"safari": HelloSafari_Auto, "ios": HelloIOS_Auto, "edge": HelloEdge_Auto, "android": HelloAndroid_11_OkHttp,
		"qq": HelloQQ_Auto, "golang": HelloGolang, "none": HelloGolang, "randomized": HelloRandomized,
		"randomizednoalpn": HelloRandomizedNoALPN,
	} {
		got, err := ParseFingerprint(name)
		if err != nil || got != want {
			t.Errorf("ParseFingerprint(%q) = %v, %v; want %v", name, got.Str(), err, want.Str())
		}
	}
	if _, err := ParseFingerprint("360"); err == nil || !strings.Contains(err.Error(), "NPN") {
		t.Errorf("360: %v", err)
	}
	if _, err := ParseFingerprint("netscape"); err == nil {
		t.Error("unknown name accepted")
	}
	if len(Fingerprints()) < 10 {
		t.Errorf("Fingerprints() = %v", Fingerprints())
	}
}

func TestDialContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			defer c.Close()
			b := make([]byte, 4096)
			c.Read(b) // read the hello, never answer
			select {}
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := DialContext(ctx, "tcp", ln.Addr().String(), clientConfig(t), HelloChrome_Auto)
		errc <- err
	}()
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("dial succeeded after cancel")
	}
}

func TestCustomFingerprintFactories(t *testing.T) {
	nilID := CustomFingerprint("Nil", "1", nil)
	if _, err := nilID.Spec(); err == nil {
		t.Fatal("nil factory accepted")
	}
	c1, _ := net.Pipe()
	if err := UClient(c1, clientConfig(t), nilID).Handshake(); err == nil {
		t.Fatal("nil factory handshake accepted")
	}
	nilSpec := CustomFingerprint("NilSpec", "1", func() (*ClientHelloSpec, error) { return nil, nil })
	if _, err := nilSpec.Spec(); err == nil {
		t.Fatal("nil spec accepted")
	}
	a := CustomFingerprint("A", "1", chrome155Spec)
	b := CustomFingerprint("A", "1", chrome155Spec)
	if a == b || a != a {
		t.Fatal("custom IDs must compare by identity")
	}
	handshakeStd(t, a, clientConfig(t), serverConfig(t), nil).ok(t)
}

// A failed Dialer.DialContext returns a nil net.Conn interface, not an
// interface holding a nil *UConn (which would pass `c != nil` checks).
func TestDialerErrorReturnsNilInterface(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // connection refused
	c, err := (&Dialer{Config: clientConfig(t)}).DialContext(context.Background(), "tcp", addr)
	if err == nil || c != nil {
		t.Fatalf("c=%#v err=%v", c, err)
	}
}

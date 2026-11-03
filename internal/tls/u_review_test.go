// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func withExt(spec *ClientHelloSpec, e TLSExtension) *ClientHelloSpec {
	n := len(spec.Extensions)
	spec.Extensions = append(spec.Extensions[:n-1:n-1], e, spec.Extensions[n-1])
	return spec
}

// RFC 8449 Section 4: a negotiated limit is enforced on incoming records.
func TestURecordSizeLimitReceive(t *testing.T) {
	run := func(honor bool) error {
		c, s := localPipe(t)
		c.SetDeadline(time.Now().Add(10 * time.Second))
		s.SetDeadline(time.Now().Add(10 * time.Second))
		srv, _ := NewTestPeer(s, testConfigServer.Clone(), TestPeerOptions{RecordSizeLimit: 0x4001, HonorClientRecordSizeLimit: honor})
		go func() {
			if srv.Handshake() == nil {
				srv.Write(bytes.Repeat([]byte("y"), 20000))
			}
			srv.Close()
		}()
		uc := NewUConn(c, testConfigClient.Clone(), withExt(testBrowserSpec(), &RecordSizeLimitExtension{Limit: 512}), false, nil)
		defer uc.Close()
		if err := uc.Handshake(); err != nil {
			return err
		}
		_, err := io.ReadFull(uc, make([]byte, 20000))
		return err
	}
	if err := run(true); err != nil {
		t.Fatalf("peer honoring the limit: %v", err)
	}
	if err := run(false); err == nil || !strings.Contains(err.Error(), "record overflow") {
		t.Fatalf("oversized record accepted: %v", err)
	}
}

func TestURecordSizeLimitBounds(t *testing.T) {
	for _, tc := range []struct {
		lim uint16
		max uint16
		ok  bool
	}{{63, 0, false}, {64, 0, true}, {16385, 0, true}, {16386, 0, false}, {16385, VersionTLS12, false}, {16384, VersionTLS12, true}} {
		spec := withExt(testBrowserSpec(), &RecordSizeLimitExtension{Limit: tc.lim})
		spec.TLSVersMax = tc.max
		scfg := testConfigServer.Clone()
		r := uHandshake(t, uOpts{spec: spec, scfg: scfg})
		if (r.cerr == nil) != tc.ok {
			t.Errorf("limit %d max %x: err=%v", tc.lim, tc.max, r.cerr)
		}
	}
}

func TestUGenericRejectsTypedExtensions(t *testing.T) {
	for _, id := range []uint16{extensionExtendedMasterSecret, extensionRenegotiationInfo, extensionStatusRequest,
		extensionSignatureAlgorithmsCert, extensionSCT, extensionSupportedPoints, extensionPreSharedKey, extensionTrustAnchors} {
		r := uHandshake(t, uOpts{spec: withExt(testBrowserSpec(), &GenericExtension{Id: id})})
		if r.cerr == nil || len(r.rec.clientHellos()) != 0 {
			t.Errorf("GenericExtension %d accepted", id)
		}
	}
}

func TestUGREASEExtensionsUnique(t *testing.T) {
	spec := testBrowserSpec()
	spec.Extensions = append([]TLSExtension{&UtlsGREASEExtension{}, &UtlsGREASEExtension{Value: 0x1a1a}, &UtlsGREASEExtension{}}, spec.Extensions...)
	for i := 0; i < 30; i++ {
		r := uHandshake(t, uOpts{spec: spec})
		r.ok(t)
		p := parseTestHello(t, r.rec.clientHellos()[0]) // parseTestHello fails on duplicates
		n := 0
		for _, id := range p.extIDs {
			if isGREASEUint16(id) {
				n++
			}
		}
		if n != 5 || !slices.Contains(p.extIDs, 0x1a1a) {
			t.Fatalf("GREASE extensions: %x", p.extIDs)
		}
	}
	dup := testBrowserSpec()
	dup.Extensions = append(dup.Extensions, &UtlsGREASEExtension{Value: 0x2a2a}, &UtlsGREASEExtension{Value: 0x2a2a})
	if dup.Validate() == nil {
		t.Fatal("duplicate fixed GREASE values accepted")
	}
}

func TestUTypedNilExtensions(t *testing.T) {
	for _, e := range []TLSExtension{(*SNIExtension)(nil), (*GenericExtension)(nil), (*KeyShareExtension)(nil), nil} {
		spec := testBrowserSpec()
		spec.Extensions = append(spec.Extensions, e)
		c := spec.Clone() // must not panic
		if c.Validate() == nil || spec.Validate() == nil {
			t.Fatalf("%T accepted", e)
		}
		r := uHandshake(t, uOpts{spec: spec})
		if r.cerr == nil {
			t.Fatalf("%T: handshake accepted", e)
		}
	}
}

// The hook sees zeroed binders when a PSK is offered; the wire carries valid ones.
func TestUHookWithPSK(t *testing.T) {
	ccfg, scfg := resumeConfigs()
	uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg}).ok(t)
	var seen []byte
	var psk bool
	r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg, hook: func(h *ClientHelloContext) error {
		copy(h.SessionID, bytes.Repeat([]byte{7}, len(h.SessionID)))
		seen, psk = slices.Clone(h.Raw), h.PSK
		return nil
	}})
	r.ok(t)
	if !psk || !r.uc.ConnectionState().DidResume {
		t.Fatalf("psk=%v resumed=%v", psk, r.uc.ConnectionState().DidResume)
	}
	wire := r.rec.clientHellos()[0]
	if len(wire) != len(seen) {
		t.Fatal("length differs")
	}
	binders := 2 + 1 + 32 // one SHA-256 binder
	if !bytes.Equal(seen[len(seen)-binders+3:], make([]byte, 32)) || bytes.Equal(wire[len(wire)-32:], make([]byte, 32)) {
		t.Fatal("hook binders not zeroed or wire binders missing")
	}
	if !bytes.Equal(seen[:len(seen)-binders], wire[:len(wire)-binders]) {
		t.Fatal("hook Raw differs from the wire outside the binders")
	}
}

func TestUHookLifecycleAndGolang(t *testing.T) {
	// Golang + hook: authentication fields reach the wire with stock key shares.
	var ek []byte
	r := uHandshake(t, uOpts{golang: true, hook: func(h *ClientHelloContext) error {
		copy(h.Random[:4], "GOGO")
		ek = h.EphemeralKey(X25519).PublicKey().Bytes()
		return nil
	}})
	r.ok(t)
	wire := r.rec.clientHellos()[0]
	if !bytes.Equal(wire[6:10], []byte("GOGO")) || !bytes.Contains(wire, ek) {
		t.Fatal("HelloGolang hook not applied")
	}
	// Golang + ECH + hook is rejected before I/O.
	ccfg, scfg, _ := testECHConfigs(t)
	r = uHandshake(t, uOpts{golang: true, ccfg: ccfg, scfg: scfg, hook: func(*ClientHelloContext) error { return nil }})
	if !errors.Is(r.cerr, ErrHookWithECH) || len(r.rec.clientHellos()) != 0 {
		t.Fatalf("golang+ECH+hook: %v", r.cerr)
	}
	// Configuration after the handshake started is an error.
	if err := r.uc.SetClientHelloHook(nil); err == nil {
		t.Fatal("SetClientHelloHook after start accepted")
	}
	if err := r.uc.SetSpec(testBrowserSpec()); err == nil {
		t.Fatal("SetSpec after start accepted")
	}
}

// Metadata getters are safe during the handshake (run with -race).
func TestUGettersDuringHandshake(t *testing.T) {
	c, s := localPipe(t)
	go func() { srv := Server(s, testConfigServer.Clone()); srv.Handshake(); srv.Close() }()
	scfg := testConfigServer.Clone()
	_ = scfg
	uc := NewUConn(c, testConfigClient.Clone(), testBrowserSpec(), false, nil)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				uc.ClientHelloRaw()
				uc.ServerHelloRaw()
				uc.ServerKeyShareData()
				uc.EphemeralKey(X25519)
				uc.NegotiatedApplicationSettings()
				uc.PeerRecordSizeLimit()
			}
		}
	}()
	err := uc.Handshake()
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if len(uc.ClientHelloRaw()) == 0 || len(uc.ServerHelloRaw()) == 0 {
		t.Fatal("snapshots missing")
	}
	uc.Close()
}

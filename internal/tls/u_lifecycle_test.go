// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// testBrowserSpec is a Chrome-shaped spec exercising every dynamic feature.
func testBrowserSpec() *ClientHelloSpec {
	return &ClientHelloSpec{
		CipherSuites: []uint16{GREASEPlaceholder, TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256},
		CompressionMethods: []uint8{0},
		Extensions: []TLSExtension{
			&UtlsGREASEExtension{},
			&SNIExtension{},
			&ExtendedMasterSecretExtension{},
			&RenegotiationInfoExtension{},
			&SupportedCurvesExtension{[]CurveID{GREASEPlaceholder, X25519MLKEM768, X25519, CurveP256, CurveP384}},
			&SupportedPointsExtension{[]uint8{0}},
			&SessionTicketExtension{},
			&ALPNExtension{[]string{"h2", "http/1.1"}},
			&StatusRequestExtension{},
			&SignatureAlgorithmsExtension{[]SignatureScheme{GREASEPlaceholder, MLDSA44, MLDSA65, MLDSA87,
				ECDSAWithP256AndSHA256, PSSWithSHA256, PKCS1WithSHA256, ECDSAWithP384AndSHA384, PSSWithSHA384,
				PKCS1WithSHA384, PSSWithSHA512, PKCS1WithSHA512, Ed25519}},
			&SCTExtension{},
			&KeyShareExtension{KeyShares: []KeyShareEntry{{Group: GREASEPlaceholder, Data: []byte{0}}, {Group: X25519MLKEM768}, {Group: X25519}}},
			&PSKKeyExchangeModesExtension{[]uint8{pskModeDHE}},
			&SupportedVersionsExtension{[]uint16{GREASEPlaceholder, VersionTLS13, VersionTLS12}},
			&CompressCertificateExtension{[]CertCompressionAlgo{CertCompressionBrotli}},
			&ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}, CodePoint: extensionApplicationSettingsNew},
			&EncryptedClientHelloExtension{GREASE: true},
			&UtlsGREASEExtension{Body: []byte{0}},
			&UtlsPaddingExtension{GetPaddingLen: BoringPaddingStyle},
		},
	}
}

// uWireRecorder records everything the client writes.
type uWireRecorder struct {
	net.Conn
	mu  sync.Mutex
	out bytes.Buffer
}

func (r *uWireRecorder) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.out.Write(b)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

type wireRecord struct {
	typ     uint8
	payload []byte
}

func (r *uWireRecorder) records() []wireRecord {
	r.mu.Lock()
	b := slices.Clone(r.out.Bytes())
	r.mu.Unlock()
	var out []wireRecord
	for len(b) >= 5 {
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			break
		}
		out = append(out, wireRecord{b[0], b[5 : 5+n]})
		b = b[5+n:]
	}
	return out
}

// clientHellos returns the plaintext ClientHello messages sent.
func (r *uWireRecorder) clientHellos() [][]byte {
	var hs [][]byte
	for _, rec := range r.records() {
		if recordType(rec.typ) == recordTypeHandshake && len(rec.payload) > 4 && rec.payload[0] == typeClientHello {
			hs = append(hs, rec.payload)
		}
	}
	return hs
}

type parsedHello struct {
	vers      uint16
	random    []byte
	sessionID []byte
	ciphers   []uint16
	extIDs    []uint16
	ext       map[uint16][]byte
}

func parseTestHello(t *testing.T, raw []byte) *parsedHello {
	t.Helper()
	p := &parsedHello{ext: map[uint16][]byte{}}
	s := cryptobyte.String(raw)
	var body, sid, cs, comp, exts cryptobyte.String
	if !s.Skip(1) || !s.ReadUint24LengthPrefixed(&body) || !s.Empty() ||
		!body.ReadUint16(&p.vers) || !body.ReadBytes(&p.random, 32) || !body.ReadUint8LengthPrefixed(&sid) ||
		!body.ReadUint16LengthPrefixed(&cs) || !body.ReadUint8LengthPrefixed(&comp) || !body.ReadUint16LengthPrefixed(&exts) || !body.Empty() {
		t.Fatalf("malformed ClientHello %x", raw)
	}
	p.sessionID = []byte(sid)
	for !cs.Empty() {
		var c uint16
		cs.ReadUint16(&c)
		p.ciphers = append(p.ciphers, c)
	}
	for !exts.Empty() {
		var id uint16
		var d cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&d) {
			t.Fatal("malformed extension")
		}
		if _, dup := p.ext[id]; dup {
			t.Fatalf("duplicate extension %d", id)
		}
		p.extIDs = append(p.extIDs, id)
		p.ext[id] = []byte(d)
	}
	return p
}

func (p *parsedHello) sni() string {
	d, ok := p.ext[extensionServerName]
	if !ok {
		return ""
	}
	return string(d[5:])
}

func (p *parsedHello) keyShareGroups() []uint16 {
	s := cryptobyte.String(p.ext[extensionKeyShare])
	var list cryptobyte.String
	s.ReadUint16LengthPrefixed(&list)
	var out []uint16
	for !list.Empty() {
		var g uint16
		var d cryptobyte.String
		list.ReadUint16(&g)
		list.ReadUint16LengthPrefixed(&d)
		out = append(out, g)
	}
	return out
}

type uOpts struct {
	spec      *ClientHelloSpec
	golang    bool
	hook      func(*ClientHelloContext) error
	session   *ClientSessionState
	peer      *TestPeerOptions
	ccfg, scfg *Config
}

type uResult struct {
	uc         *UConn
	rec        *uWireRecorder
	cerr, serr error
	sconn      *Conn
	peer       *TestPeerResult
}

// uHandshake runs a uTLS client against the mirrored server (or test peer)
// over loopback and exchanges one byte each way (to receive session tickets).
func uHandshake(t *testing.T, o uOpts) *uResult {
	t.Helper()
	c, s := localPipe(t)
	deadline := time.Now().Add(20 * time.Second)
	c.SetDeadline(deadline)
	s.SetDeadline(deadline)
	ccfg, scfg := o.ccfg, o.scfg
	if ccfg == nil {
		ccfg = testConfigClient.Clone()
	}
	if scfg == nil {
		scfg = testConfigServer.Clone()
	}
	res := &uResult{rec: &uWireRecorder{Conn: c}}
	var srv *Conn
	if o.peer != nil {
		srv, res.peer = NewTestPeer(s, scfg, *o.peer)
	} else {
		srv = Server(s, scfg)
	}
	res.sconn = srv
	done := make(chan error, 1)
	go func() {
		err := srv.Handshake()
		if err == nil {
			buf := make([]byte, 1)
			if _, err = io.ReadFull(srv, buf); err == nil {
				_, err = srv.Write([]byte("s"))
			}
		}
		done <- err
		srv.Close()
	}()
	uc := NewUConn(res.rec, ccfg, o.spec, o.golang, nil)
	if o.hook != nil {
		uc.SetClientHelloHook(o.hook)
	}
	if o.session != nil {
		if err := uc.SetSession(o.session); err != nil {
			t.Fatal(err)
		}
	}
	res.uc = uc
	res.cerr = uc.HandshakeContext(context.Background())
	if res.cerr == nil {
		if _, err := uc.Write([]byte("c")); err != nil {
			res.cerr = err
		} else {
			buf := make([]byte, 1)
			_, res.cerr = io.ReadFull(uc, buf)
		}
	}
	if res.cerr != nil {
		c.Close()
	}
	res.serr = <-done
	uc.Close()
	return res
}

func (r *uResult) ok(t *testing.T) {
	t.Helper()
	if r.cerr != nil || r.serr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", r.cerr, r.serr)
	}
}

func TestUBasicTLS13AndTLS12(t *testing.T) {
	r := uHandshake(t, uOpts{spec: testBrowserSpec()})
	r.ok(t)
	if v := r.uc.ConnectionState().Version; v != VersionTLS13 {
		t.Fatalf("version %x", v)
	}
	if g := r.uc.ConnectionState().CurveID; g != X25519MLKEM768 {
		t.Fatalf("curve %v", g)
	}
	scfg := testConfigServer.Clone()
	scfg.MaxVersion = VersionTLS12
	r = uHandshake(t, uOpts{spec: testBrowserSpec(), scfg: scfg})
	r.ok(t)
	if v := r.uc.ConnectionState().Version; v != VersionTLS12 {
		t.Fatalf("version %x", v)
	}
}

func TestUWireInvariants(t *testing.T) {
	seen := map[uint16]bool{}
	for i := 0; i < 24; i++ {
		r := uHandshake(t, uOpts{spec: testBrowserSpec()})
		r.ok(t)
		hs := r.rec.clientHellos()
		if len(hs) != 1 {
			t.Fatalf("%d hellos", len(hs))
		}
		p := parseTestHello(t, hs[0])
		if p.vers != VersionTLS12 {
			t.Fatalf("legacy_version %#04x, want 0x0303 (RFC 8446 4.1.2)", p.vers)
		}
		groups := cryptobyte.String(p.ext[extensionSupportedCurves][2:])
		var groupGREASE uint16
		groups.ReadUint16(&groupGREASE)
		ks := p.keyShareGroups()
		if !isGREASEUint16(groupGREASE) || ks[0] != groupGREASE {
			t.Fatalf("key_share GREASE %#04x != supported_groups GREASE %#04x", ks[0], groupGREASE)
		}
		var g1, g2 uint16
		for _, id := range p.extIDs {
			if isGREASEUint16(id) {
				if g1 == 0 {
					g1 = id
				} else {
					g2 = id
				}
			}
		}
		if g1 == 0 || g2 == 0 || g1 == g2 {
			t.Fatalf("GREASE extensions %#04x %#04x", g1, g2)
		}
		seen[g1], seen[ks[0]], seen[p.ciphers[0]] = true, true, true
		if p.extIDs[len(p.extIDs)-1] != extensionPadding && len(hs[0]) < 512 {
			t.Fatalf("padding not last")
		}
		if _, ok := p.ext[extensionEncryptedClientHello]; !ok {
			t.Fatal("GREASE ECH missing")
		}
		ech := p.ext[extensionEncryptedClientHello]
		if l := len(ech) - 8 - 32 - 2; l != 144 && l != 176 && l != 208 && l != 240 {
			t.Fatalf("GREASE ECH payload length %d", l)
		}
	}
	if len(seen) < 6 {
		t.Fatalf("GREASE values not varying across connections: %v", seen)
	}
}

func TestUSNIOmittedForIPAndEmpty(t *testing.T) {
	for _, name := range []string{"192.0.2.1", "[2001:db8::1]", ""} {
		ccfg := testConfigClient.Clone()
		ccfg.ServerName = name
		ccfg.InsecureSkipVerify = true
		r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg})
		r.ok(t)
		p := parseTestHello(t, r.rec.clientHellos()[0])
		if _, ok := p.ext[extensionServerName]; ok {
			t.Fatalf("server_name sent for %q", name)
		}
	}
}

func TestUHelloRetryRequest(t *testing.T) {
	scfg := testConfigServer.Clone()
	scfg.CurvePreferences = []CurveID{CurveP384}
	r := uHandshake(t, uOpts{spec: testBrowserSpec(), scfg: scfg})
	r.ok(t)
	if !r.uc.ConnectionState().HelloRetryRequest || r.uc.ConnectionState().CurveID != CurveP384 {
		t.Fatalf("HRR=%v curve=%v", r.uc.ConnectionState().HelloRetryRequest, r.uc.ConnectionState().CurveID)
	}
	hs := r.rec.clientHellos()
	if len(hs) != 2 {
		t.Fatalf("%d hellos", len(hs))
	}
	p1, p2 := parseTestHello(t, hs[0]), parseTestHello(t, hs[1])
	if !bytes.Equal(p1.random, p2.random) || !bytes.Equal(p1.sessionID, p2.sessionID) {
		t.Fatal("random/session_id changed across HelloRetryRequest")
	}
	if g := p2.keyShareGroups(); len(g) != 1 || g[0] != uint16(CurveP384) {
		t.Fatalf("second key_share %v", g)
	}
	// Everything but key_share and padding must be identical (RFC 8446 4.1.2).
	for _, id := range p1.extIDs {
		if id == extensionKeyShare || id == extensionPadding {
			continue
		}
		if !bytes.Equal(p1.ext[id], p2.ext[id]) {
			t.Fatalf("extension %d changed across HRR", id)
		}
	}
	if !slices.Equal(p1.ciphers, p2.ciphers) {
		t.Fatal("cipher suites changed across HRR")
	}
}

func resumeConfigs() (*Config, *Config) {
	ccfg, scfg := testConfigClient.Clone(), testConfigServer.Clone()
	ccfg.ClientSessionCache = NewLRUClientSessionCache(4)
	return ccfg, scfg
}

func TestUResumption(t *testing.T) {
	for _, tc := range []struct {
		name string
		max  uint16
		hrr  bool
		hook bool
	}{{"tls13", VersionTLS13, false, false}, {"tls12", VersionTLS12, false, false},
		{"tls13+hrr", VersionTLS13, true, false}, {"tls13+hook", VersionTLS13, false, true}, {"tls12+hook", VersionTLS12, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ccfg, scfg := resumeConfigs()
			scfg.MaxVersion = tc.max
			if tc.hrr {
				scfg.CurvePreferences = []CurveID{CurveP384}
			}
			var hook func(*ClientHelloContext) error
			if tc.hook {
				hook = func(h *ClientHelloContext) error {
					copy(h.SessionID, bytes.Repeat([]byte{0xab}, len(h.SessionID)))
					copy(h.Random[:8], "uTLSauth")
					return nil
				}
			}
			r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg, hook: hook})
			r.ok(t)
			if r.uc.ConnectionState().DidResume {
				t.Fatal("first connection resumed")
			}
			r = uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg, hook: hook})
			r.ok(t)
			if !r.uc.ConnectionState().DidResume {
				t.Fatal("second connection did not resume")
			}
			p := parseTestHello(t, r.rec.clientHellos()[0])
			if tc.max == VersionTLS13 {
				if p.extIDs[len(p.extIDs)-1] != extensionPreSharedKey {
					t.Fatal("pre_shared_key is not the last extension")
				}
			} else if len(p.ext[extensionSessionTicket]) == 0 {
				t.Fatal("TLS 1.2 resumption did not send the ticket")
			}
			if tc.hook && !bytes.Equal(p.random[:8], []byte("uTLSauth")) {
				t.Fatal("hook random not on the wire")
			}
		})
	}
}

func TestUHookRules(t *testing.T) {
	r := uHandshake(t, uOpts{spec: testBrowserSpec(), hook: func(h *ClientHelloContext) error {
		h.Raw[len(h.Raw)-1] ^= 1
		return nil
	}})
	if r.cerr == nil || !strings.Contains(r.cerr.Error(), "other than Random and SessionID") {
		t.Fatalf("modifying other bytes: %v", r.cerr)
	}
	r = uHandshake(t, uOpts{spec: testBrowserSpec(), hook: func(h *ClientHelloContext) error {
		h.SessionID = make([]byte, 32)
		return nil
	}})
	if r.cerr == nil {
		t.Fatal("replacing the SessionID slice was accepted")
	}
	wantErr := errors.New("abort")
	r = uHandshake(t, uOpts{spec: testBrowserSpec(), hook: func(h *ClientHelloContext) error { return wantErr }})
	if !errors.Is(r.cerr, wantErr) {
		t.Fatalf("hook error not propagated: %v", r.cerr)
	}
	if len(r.rec.clientHellos()) != 0 {
		t.Fatal("ClientHello sent although the hook failed")
	}
	// Ephemeral keys are available to the hook and match the key share sent.
	var ek []byte
	r = uHandshake(t, uOpts{spec: testBrowserSpec(), hook: func(h *ClientHelloContext) error {
		ek = h.EphemeralKey(X25519).PublicKey().Bytes()
		return nil
	}})
	r.ok(t)
	if !bytes.Contains(r.rec.clientHellos()[0], ek) {
		t.Fatal("EphemeralKey does not match the X25519 key share")
	}
}

func testECHConfigs(t *testing.T) (*Config, *Config, []byte) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"public.example"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	pubDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	tmpl.DNSNames[0] = "secret.example"
	secDER, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	pub, _ := x509.ParseCertificate(pubDER)
	sec, _ := x509.ParseCertificate(secDER)
	echKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16(extensionEncryptedClientHello)
	b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(7)
		b.AddUint16(0x0020)
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(echKey.PublicKey().Bytes()) })
		b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddUint16(1); b.AddUint16(1) })
		b.AddUint8(32)
		b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes([]byte("public.example")) })
		b.AddUint16(0)
	})
	cfg := b.BytesOrPanic()
	lb := cryptobyte.NewBuilder(nil)
	lb.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(cfg) })
	list := lb.BytesOrPanic()
	ccfg, scfg := testConfigClient.Clone(), testConfigServer.Clone()
	ccfg.Time, scfg.Time = nil, nil
	ccfg.MinVersion, scfg.MinVersion = VersionTLS13, VersionTLS13
	ccfg.ServerName = "secret.example"
	ccfg.RootCAs = x509.NewCertPool()
	ccfg.RootCAs.AddCert(pub)
	ccfg.RootCAs.AddCert(sec)
	ccfg.EncryptedClientHelloConfigList = list
	scfg.Certificates = []Certificate{{Certificate: [][]byte{pubDER}, PrivateKey: k}, {Certificate: [][]byte{secDER}, PrivateKey: k}}
	scfg.EncryptedClientHelloKeys = []EncryptedClientHelloKey{{Config: cfg, PrivateKey: echKey.Bytes(), SendAsRetry: true}}
	return ccfg, scfg, list
}

func TestUECH(t *testing.T) {
	for _, tc := range []struct {
		name   string
		hrr    bool
		resume bool
	}{{"basic", false, false}, {"hrr", true, false}, {"resume", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			ccfg, scfg, _ := testECHConfigs(t)
			if tc.hrr {
				scfg.CurvePreferences = []CurveID{CurveP384}
			}
			if tc.resume {
				ccfg.ClientSessionCache = NewLRUClientSessionCache(2)
				r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg})
				r.ok(t)
			}
			r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg})
			r.ok(t)
			cs := r.uc.ConnectionState()
			if !cs.ECHAccepted || cs.ServerName != "secret.example" {
				t.Fatalf("ECHAccepted=%v ServerName=%q", cs.ECHAccepted, cs.ServerName)
			}
			if tc.resume && !cs.DidResume {
				t.Fatal("ECH resumption did not resume")
			}
			for i, raw := range r.rec.clientHellos() {
				p := parseTestHello(t, raw)
				if p.sni() != "public.example" || bytes.Contains(raw, []byte("secret.example")) {
					t.Fatalf("hello %d leaks the private name (sni=%q)", i, p.sni())
				}
				if len(p.ext[extensionEncryptedClientHello]) < 20 {
					t.Fatalf("hello %d has no real ECH payload", i)
				}
				if _, ok := p.ext[extensionApplicationSettingsNew]; !ok {
					t.Fatalf("hello %d lost the fingerprint shape", i)
				}
			}
		})
	}
}

func TestUECHRejectedNeverLeaksName(t *testing.T) {
	ccfg, scfg, _ := testECHConfigs(t)
	_, _, other := testECHConfigs(t) // a config whose key the server does not have
	ccfg.EncryptedClientHelloConfigList = other
	r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg})
	var rej *ECHRejectionError
	if !errors.As(r.cerr, &rej) {
		t.Fatalf("err = %v, want ECHRejectionError", r.cerr)
	}
	for _, raw := range r.rec.clientHellos() {
		if bytes.Contains(raw, []byte("secret.example")) {
			t.Fatal("private name sent in clear")
		}
	}
	// A hook cannot see ClientHelloInner bytes: rejected before any I/O.
	ccfg2, scfg2, _ := testECHConfigs(t)
	r = uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg2, scfg: scfg2, hook: func(*ClientHelloContext) error { return nil }})
	if !errors.Is(r.cerr, ErrHookWithECH) || len(r.rec.clientHellos()) != 0 {
		t.Fatalf("hook+ECH: err=%v hellos=%d", r.cerr, len(r.rec.clientHellos()))
	}
}

func TestUInjectedSession(t *testing.T) {
	for _, vers := range []uint16{VersionTLS13, VersionTLS12} {
		ccfg, scfg := resumeConfigs()
		scfg.MaxVersion = vers
		r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg})
		r.ok(t)
		cs, ok := ccfg.ClientSessionCache.Get(ccfg.ServerName)
		if !ok {
			t.Fatal("no session cached")
		}
		// Re-inject through the public constructor (as an out-of-band ticket would be).
		st := cs.session
		inj, err := NewSessionState(st.version, st.cipherSuite, st.secret, st.ticket, st.extMasterSecret,
			time.Unix(int64(st.createdAt), 0), st.ageAdd, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		ccfg2 := testConfigClient.Clone()
		ccfg2.InsecureSkipVerify = true // injected sessions carry no certificates
		r = uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg2, scfg: scfg, session: inj})
		r.ok(t)
		if !r.uc.ConnectionState().DidResume {
			t.Fatalf("%x: injected session not resumed", vers)
		}
	}
}

func TestUCertificateCompression(t *testing.T) {
	for _, alg := range []CertCompressionAlgo{CertCompressionBrotli, CertCompressionZlib, CertCompressionZstd} {
		spec := testBrowserSpec()
		for i, e := range spec.Extensions {
			if _, ok := e.(*CompressCertificateExtension); ok {
				spec.Extensions[i] = &CompressCertificateExtension{[]CertCompressionAlgo{alg}}
			}
		}
		r := uHandshake(t, uOpts{spec: spec, peer: &TestPeerOptions{CompressCertificate: alg}})
		r.ok(t)
		if got := r.peer.Snapshot().CompressedWith; got != alg {
			t.Fatalf("peer did not compress with %d (got %d)", alg, got)
		}
		if len(r.uc.ConnectionState().PeerCertificates) == 0 {
			t.Fatal("no peer certificates after decompression")
		}
	}
	// Malformed inputs must fail the handshake with bad_certificate.
	bad := map[string]func(*compressedCertificateMsg){
		"length too large": func(m *compressedCertificateMsg) { m.uncompressedLength++ },
		"length too small": func(m *compressedCertificateMsg) { m.uncompressedLength-- },
		"over cap":         func(m *compressedCertificateMsg) { m.uncompressedLength = maxDecompressedCertificate + 1 },
		"trailing input":   func(m *compressedCertificateMsg) { m.compressed = append(m.compressed, 0) },
		"corrupt stream":   func(m *compressedCertificateMsg) { m.compressed[len(m.compressed)/2] ^= 0xff },
		"wrong algorithm":  func(m *compressedCertificateMsg) { m.algorithm = uint16(CertCompressionZlib) },
	}
	for name, f := range bad {
		r := uHandshake(t, uOpts{spec: testBrowserSpec(), peer: &TestPeerOptions{CompressCertificate: CertCompressionBrotli, CorruptCompressed: f}})
		if r.cerr == nil {
			t.Fatalf("%s: handshake succeeded", name)
		}
	}
}

func TestUALPS(t *testing.T) {
	for _, cp := range []uint16{extensionApplicationSettings, extensionApplicationSettingsNew} {
		spec := testBrowserSpec()
		for i, e := range spec.Extensions {
			if _, ok := e.(*ApplicationSettingsExtension); ok {
				spec.Extensions[i] = &ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}, CodePoint: cp, Settings: []byte{0, 3, 0, 0, 0, 100}}
			}
		}
		scfg := testConfigServer.Clone()
		scfg.NextProtos = []string{"h2"}
		r := uHandshake(t, uOpts{spec: spec, scfg: scfg, peer: &TestPeerOptions{ALPSSettings: map[string][]byte{"h2": {1, 2, 3}}}})
		r.ok(t)
		got, ok := r.uc.NegotiatedApplicationSettings()
		if !ok || !bytes.Equal(got, []byte{1, 2, 3}) {
			t.Fatalf("cp %d: client ALPS = %x %v", cp, got, ok)
		}
		snap := r.peer.Snapshot()
		if snap.ALPSCodepoint != cp || !snap.ClientALPSReceived || !bytes.Equal(snap.ClientALPSSettings, []byte{0, 3, 0, 0, 0, 100}) {
			t.Fatalf("cp %d: peer saw codepoint %d received=%v settings=%x", cp, snap.ALPSCodepoint, snap.ClientALPSReceived, snap.ClientALPSSettings)
		}
	}
	// ALPS is not negotiated for a protocol it was not offered for.
	scfg := testConfigServer.Clone()
	scfg.NextProtos = []string{"http/1.1"}
	r := uHandshake(t, uOpts{spec: testBrowserSpec(), scfg: scfg, peer: &TestPeerOptions{ALPSSettings: map[string][]byte{"http/1.1": {1}}}})
	r.ok(t)
	if _, ok := r.uc.NegotiatedApplicationSettings(); ok {
		t.Fatal("ALPS negotiated for http/1.1")
	}
}

// recordSizes returns the ciphertext lengths of application data records.
func recordSizes(r *uWireRecorder) []int {
	var out []int
	for _, rec := range r.records() {
		if recordType(rec.typ) == recordTypeApplicationData {
			out = append(out, len(rec.payload))
		}
	}
	return out
}

func TestURecordSizeLimit(t *testing.T) {
	spec := testBrowserSpec()
	spec.Extensions = append(spec.Extensions[:len(spec.Extensions)-1], &RecordSizeLimitExtension{Limit: 0x4001}, spec.Extensions[len(spec.Extensions)-1])
	c, s := localPipe(t)
	rec := &uWireRecorder{Conn: c}
	srv, peer := NewTestPeer(s, testConfigServer.Clone(), TestPeerOptions{RecordSizeLimit: 256})
	go func() {
		if srv.Handshake() == nil {
			io.Copy(io.Discard, srv)
		}
		srv.Close()
	}()
	uc := NewUConn(rec, testConfigClient.Clone(), spec, false, nil)
	if err := uc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if _, err := uc.Write(bytes.Repeat([]byte("x"), 5000)); err != nil {
		t.Fatal(err)
	}
	uc.Close()
	if uc.PeerRecordSizeLimit() != 255 {
		t.Fatalf("limit %d", uc.PeerRecordSizeLimit())
	}
	if peer.Snapshot().OfferedRecordSizeLimit != 0x4001 {
		t.Fatal("record_size_limit not offered")
	}
	for _, n := range recordSizes(rec) {
		if n > 256+16 { // limit (incl. content type) + AEAD tag
			t.Fatalf("record of %d bytes exceeds the server's limit", n)
		}
	}
	// Unsolicited record_size_limit is rejected.
	r := uHandshake(t, uOpts{spec: testBrowserSpec(), peer: &TestPeerOptions{UnsolicitedRecordSizeLimit: true}})
	if r.cerr == nil {
		t.Fatal("unsolicited record_size_limit accepted")
	}
}

func TestUConfigPrecedence(t *testing.T) {
	// ALPN override.
	ccfg := testConfigClient.Clone()
	ccfg.NextProtos = []string{"http/1.1"}
	scfg := testConfigServer.Clone()
	scfg.NextProtos = []string{"h2", "http/1.1"}
	r := uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg, scfg: scfg})
	r.ok(t)
	if p := r.uc.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("negotiated %q", p)
	}
	if _, ok := parseTestHello(t, r.rec.clientHellos()[0]).ext[extensionApplicationSettingsNew]; ok {
		t.Fatal("ALPS sent for a protocol not in ALPN")
	}
	// Versions: Config.MaxVersion and spec TLSVersMax.
	for _, mod := range []func(*Config, *ClientHelloSpec){
		func(c *Config, s *ClientHelloSpec) { c.MaxVersion = VersionTLS12 },
		func(c *Config, s *ClientHelloSpec) { s.TLSVersMax = VersionTLS12 },
	} {
		ccfg, spec := testConfigClient.Clone(), testBrowserSpec()
		mod(ccfg, spec)
		r := uHandshake(t, uOpts{spec: spec, ccfg: ccfg})
		r.ok(t)
		if r.uc.ConnectionState().Version != VersionTLS12 {
			t.Fatal("TLS 1.3 negotiated despite a TLS 1.2 maximum")
		}
		p := parseTestHello(t, r.rec.clientHellos()[0])
		if bytes.Contains(p.ext[extensionSupportedVersions], []byte{3, 4}) {
			t.Fatal("TLS 1.3 offered despite a TLS 1.2 maximum")
		}
	}
	ccfg = testConfigClient.Clone()
	ccfg.MinVersion = VersionTLS13
	spec := testBrowserSpec()
	spec.TLSVersMax = VersionTLS12
	if r := uHandshake(t, uOpts{spec: spec, ccfg: ccfg}); r.cerr == nil {
		t.Fatal("no common version accepted")
	}
	// CurvePreferences removes groups and key shares.
	ccfg = testConfigClient.Clone()
	ccfg.CurvePreferences = []CurveID{X25519, CurveP256}
	r = uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg})
	r.ok(t)
	if g := parseTestHello(t, r.rec.clientHellos()[0]).keyShareGroups(); len(g) != 2 || g[1] != uint16(X25519) {
		t.Fatalf("key shares %v", g)
	}
	// Config.CipherSuites removes TLS 1.2 suites.
	ccfg = testConfigClient.Clone()
	ccfg.CipherSuites = []uint16{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384}
	r = uHandshake(t, uOpts{spec: testBrowserSpec(), ccfg: ccfg})
	r.ok(t)
	cs := parseTestHello(t, r.rec.clientHellos()[0]).ciphers
	if slices.Contains(cs, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) || !slices.Contains(cs, TLS_AES_128_GCM_SHA256) {
		t.Fatalf("ciphers %x", cs)
	}
	// NextProtos with a spec lacking ALPN is an error, not a silent drop.
	spec = testBrowserSpec()
	spec.Extensions = slices.DeleteFunc(spec.Extensions, func(e TLSExtension) bool { _, ok := e.(*ALPNExtension); return ok })
	ccfg = testConfigClient.Clone()
	ccfg.NextProtos = []string{"h2"}
	if r := uHandshake(t, uOpts{spec: spec, ccfg: ccfg}); r.cerr == nil {
		t.Fatal("NextProtos without ALPN extension accepted")
	}
}

func TestUNoSpecNeverFallsBack(t *testing.T) {
	r := uHandshake(t, uOpts{})
	if !errors.Is(r.cerr, ErrNoSpec) || len(r.rec.clientHellos()) != 0 {
		t.Fatalf("err=%v hellos=%d", r.cerr, len(r.rec.clientHellos()))
	}
	r = uHandshake(t, uOpts{golang: true})
	r.ok(t)
}

func TestUSpecValidation(t *testing.T) {
	cases := map[string]func(*ClientHelloSpec){
		"duplicate":      func(s *ClientHelloSpec) { s.Extensions = append(s.Extensions, &SNIExtension{}) },
		"generic psk":    func(s *ClientHelloSpec) { s.Extensions = append(s.Extensions, &GenericExtension{Id: extensionPreSharedKey}) },
		"explicit share": func(s *ClientHelloSpec) { s.Extensions[11] = &KeyShareExtension{KeyShares: []KeyShareEntry{{Group: X25519, Data: []byte{1}}}} },
		"no ciphers":     func(s *ClientHelloSpec) { s.CipherSuites = nil },
		"huge alpn":      func(s *ClientHelloSpec) { s.Extensions[7] = &ALPNExtension{[]string{strings.Repeat("a", 256)}} },
		"alpn too long": func(s *ClientHelloSpec) {
			var ps []string
			for i := 0; i < 400; i++ {
				ps = append(ps, strings.Repeat("p", 200))
			}
			s.Extensions[7] = &ALPNExtension{ps}
		},
		"bad compression alg": func(s *ClientHelloSpec) { s.Extensions[15] = &CompressCertificateExtension{[]CertCompressionAlgo{99}} },
		"no key_share for 1.3": func(s *ClientHelloSpec) { s.Extensions[11] = &GenericExtension{Id: 0xfff0} },
	}
	for name, mod := range cases {
		spec := testBrowserSpec()
		mod(spec)
		r := uHandshake(t, uOpts{spec: spec})
		if r.cerr == nil {
			t.Errorf("%s: accepted", name)
		}
		if len(r.rec.clientHellos()) != 0 {
			t.Errorf("%s: hello sent despite invalid spec", name)
		}
	}
}

func TestUSpecIsolation(t *testing.T) {
	spec := testBrowserSpec()
	c1, _ := net.Pipe()
	u := NewUConn(c1, testConfigClient.Clone(), spec, false, nil)
	spec.Extensions[1] = &SNIExtension{ServerName: "mutated.example"}
	if _, ok := u.spec.Extensions[1].(*SNIExtension); !ok || u.spec.Extensions[1].(*SNIExtension).ServerName != "" {
		t.Fatal("UConn shares the caller's spec")
	}
}

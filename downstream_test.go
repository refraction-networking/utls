// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

// Migration fixtures for the three downstream projects with the deepest uTLS
// integration. Each test reproduces the project's protocol-level use of uTLS
// v1 with the v2 API, against a loopback server that independently verifies
// what the client put on the wire. docs/MIGRATION.md maps the v1 calls.
//
//   (Xray-core REALITY is tested against the real XTLS/REALITY server in the
//   isolated module interop/reality.)
//   sing-box ShadowTLS v3, PQ opt-out, ALPN, ECH (common/tls/utls_client.go,
//     protocol/shadowtls; v1 fork: SessionIDGenerator)
//   Psiphon tunnel-core (psiphon/tlsDialer.go: seeded randomized profiles,
//     passthrough client random, obfuscated session tickets, fragmentation)

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// peekedHello is a ClientHello read off the wire by a test server before it
// hands the connection to crypto/tls.
type peekedHello struct {
	record []byte // complete first record
	msg    []byte // handshake message (record[5:])
	random []byte
	sid    []byte
	x25519 []byte // X25519 key share (or the classical half of X25519MLKEM768)
	groups []uint16
}

func peekHello(c net.Conn) (*peekedHello, error) {
	// Reassemble the handshake message across records (it may be fragmented).
	p := &peekedHello{}
	for len(p.msg) < 4 || len(p.msg) < 4+(int(p.msg[1])<<16|int(p.msg[2])<<8|int(p.msg[3])) {
		hdr := make([]byte, 5)
		if _, err := io.ReadFull(c, hdr); err != nil {
			return nil, err
		}
		if hdr[0] != 22 {
			return nil, errors.New("not a handshake record")
		}
		body := make([]byte, int(hdr[3])<<8|int(hdr[4]))
		if _, err := io.ReadFull(c, body); err != nil {
			return nil, err
		}
		p.record = append(append(p.record, hdr...), body...)
		p.msg = append(p.msg, body...)
	}
	s := cryptobyte.String(p.msg)
	var x, sid, exts cryptobyte.String
	if !s.Skip(4+2) || !s.ReadBytes((*[]byte)(&p.random), 32) || !s.ReadUint8LengthPrefixed(&sid) ||
		!s.ReadUint16LengthPrefixed(&x) || !s.ReadUint8LengthPrefixed(&x) || !s.ReadUint16LengthPrefixed(&exts) {
		return nil, errors.New("malformed ClientHello")
	}
	p.sid = sid
	var hybridHalf []byte
	for !exts.Empty() {
		var id uint16
		var d cryptobyte.String
		if !exts.ReadUint16(&id) || !exts.ReadUint16LengthPrefixed(&d) {
			return nil, errors.New("malformed extensions")
		}
		if id != 51 {
			continue
		}
		var list cryptobyte.String
		d.ReadUint16LengthPrefixed(&list)
		for !list.Empty() {
			var g uint16
			var k cryptobyte.String
			list.ReadUint16(&g)
			list.ReadUint16LengthPrefixed(&k)
			p.groups = append(p.groups, g)
			switch {
			case g == 29 && p.x25519 == nil:
				p.x25519 = k
			case g == 4588 && len(k) == 1216:
				hybridHalf = k[1184:]
			}
		}
	}
	// Like Xray's server: the X25519 share, else the hybrid's X25519 half.
	if p.x25519 == nil {
		p.x25519 = hybridHalf
	}
	return p, nil
}

// prefixConn replays already-read bytes before the rest of the stream.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func replay(c net.Conn, prefix []byte) net.Conn {
	return &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(prefix), c)}
}

// serveOnce accepts one connection, peeks its ClientHello and runs handle.
func serveOnce(t *testing.T, handle func(c net.Conn, h *peekedHello) error) (string, <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		defer ln.Close()
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		h, err := peekHello(c)
		if err != nil {
			errc <- err
			return
		}
		errc <- handle(c, h)
	}()
	return ln.Addr().String(), errc
}

// ---------------------------------------------------------------------------
// sing-box

// shadowTLSv3SessionID is ShadowTLS v3's session ID: 28 random bytes and a
// 4-byte HMAC-SHA1(password) over the ClientHello with those 4 bytes zeroed.
// v1 (sagernet fork): config.SessionIDGenerator = func(hello, sid []byte) error.
// v2: a ClientHello hook.
func shadowTLSv3Hook(password []byte) func(*ClientHelloContext) error {
	return func(ctx *ClientHelloContext) error {
		if len(ctx.SessionID) != 32 {
			return errors.New("shadowtls: session ID must be 32 bytes")
		}
		rand.Read(ctx.SessionID[:28])
		clear(ctx.SessionID[28:])
		m := bytes.Clone(ctx.Raw)
		copy(m[39:71], ctx.SessionID)
		h := hmac.New(sha1.New, password)
		h.Write(m)
		copy(ctx.SessionID[28:], h.Sum(nil)[:4])
		return nil
	}
}

func shadowTLSv3Verify(password []byte, h *peekedHello) bool {
	m := bytes.Clone(h.msg)
	clear(m[39+28 : 39+32])
	mac := hmac.New(sha1.New, password)
	mac.Write(m)
	return hmac.Equal(mac.Sum(nil)[:4], h.sid[28:])
}

func TestDownstreamSingBoxShadowTLS(t *testing.T) {
	password := []byte("shadowtls-password")
	scfg := serverConfig(t)
	addr, serr := serveOnce(t, func(c net.Conn, h *peekedHello) error {
		if !shadowTLSv3Verify(password, h) {
			return errors.New("shadowtls server: bad session ID HMAC")
		}
		s := tls.Server(replay(c, h.record), scfg)
		return s.Handshake()
	})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uc := UClient(conn, clientConfig(t), HelloChrome_Auto)
	if err := uc.SetClientHelloHook(shadowTLSv3Hook(password)); err != nil {
		t.Fatal(err)
	}
	if err := uc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serr; err != nil {
		t.Fatal(err)
	}
}

// sing-box's utls client: fingerprint by name, optional PQ opt-out (for
// middleboxes that drop large hellos), ALPN from the outbound config, ECH.
func singBoxClient(t *testing.T, conn net.Conn, fingerprint string, disablePQ bool, alpn []string, echList []byte, serverName string) *UConn {
	id, err := ParseFingerprint(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	cfg := clientConfig(t)
	cfg.ServerName = serverName
	cfg.NextProtos = alpn // overrides the fingerprint's ALPN list
	if echList != nil {
		cfg.MinVersion = tls.VersionTLS13
		cfg.EncryptedClientHelloConfigList = echList
	}
	if !disablePQ {
		return UClient(conn, cfg, id)
	}
	spec, err := id.Spec()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range spec.Extensions {
		switch e := e.(type) {
		case *SupportedCurvesExtension:
			e.Curves = slices.DeleteFunc(e.Curves, func(c CurveID) bool { return c == X25519MLKEM768 })
		case *KeyShareExtension:
			e.KeyShares = slices.DeleteFunc(e.KeyShares, func(k KeyShareEntry) bool { return k.Group == X25519MLKEM768 })
			e.ReuseClassicalFromHybrid = false
		}
	}
	uc := UClient(conn, cfg, HelloCustom)
	if err := uc.ApplyPreset(spec); err != nil {
		t.Fatal(err)
	}
	return uc
}

func TestDownstreamSingBoxOptions(t *testing.T) {
	scfg := serverConfig(t)
	// PQ opt-out + ALPN override.
	addr, serr := serveOnce(t, func(c net.Conn, h *peekedHello) error {
		if slices.Contains(h.groups, 4588) {
			return errors.New("X25519MLKEM768 offered despite the opt-out")
		}
		s := tls.Server(replay(c, h.record), scfg)
		if err := s.Handshake(); err != nil {
			return err
		}
		if p := s.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
			return errors.New("ALPN " + p)
		}
		return nil
	})
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uc := singBoxClient(t, conn, "chrome", true, []string{"http/1.1"}, nil, "utls.test")
	if err := uc.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := <-serr; err != nil {
		t.Fatal(err)
	}
	if st := uc.ConnectionState(); st.NegotiatedProtocol != "http/1.1" || st.CurveID != tls.X25519 {
		t.Fatalf("state: alpn %q curve %v", st.NegotiatedProtocol, st.CurveID)
	}

	// ECH with the fingerprint, against crypto/tls.
	list, keys := echPair(t)
	escfg := serverConfig(t)
	escfg.MinVersion = tls.VersionTLS13
	escfg.EncryptedClientHelloKeys = keys
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			s := tls.Server(c, escfg)
			s.Handshake()
			s.Close()
		}
	}()
	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	rec := &recConn{Conn: conn2}
	uc2 := singBoxClient(t, rec, "firefox", false, nil, list, "secret.example")
	if err := uc2.Handshake(); err != nil {
		t.Fatal(err)
	}
	if !uc2.ConnectionState().ECHAccepted || bytes.Contains(rec.written(), []byte("secret.example")) {
		t.Fatal("ECH not used")
	}
}

// ---------------------------------------------------------------------------
// Psiphon

// passthroughRandom is Psiphon's TLS passthrough message: the client random is
// a nonce and a MAC under the obfuscation key, so the server can tell clients
// from probes (which it relays to a real site).
func passthroughHook(key []byte) func(*ClientHelloContext) error {
	return func(ctx *ClientHelloContext) error {
		rand.Read(ctx.Random[:16])
		h := hmac.New(sha256.New, key)
		h.Write(ctx.Random[:16])
		copy(ctx.Random[16:], h.Sum(nil)[:16])
		return nil
	}
}

func passthroughVerify(key, random []byte) bool {
	h := hmac.New(sha256.New, key)
	h.Write(random[:16])
	return hmac.Equal(h.Sum(nil)[:16], random[16:])
}

// serverSessionBytes encodes a server-side crypto/tls SessionState for a TLS
// 1.2 session with master secret secret (crypto/tls ticket.go layout).
func serverSessionBytes(suite uint16, secret []byte, curve tls.CurveID) []byte {
	var b cryptobyte.Builder
	b.AddUint16(tls.VersionTLS12)
	b.AddUint8(1) // server
	b.AddUint16(suite)
	b.AddUint64(uint64(time.Now().Unix()))
	b.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) { b.AddBytes(secret) })
	b.AddUint24(0) // extra
	b.AddUint8(1)  // extended master secret
	b.AddUint8(0)  // early data
	b.AddUint24(0) // certificate list
	b.AddUint24(0) // verified chains
	b.AddUint16(uint16(curve))
	return b.BytesOrPanic()
}

func TestDownstreamPsiphon(t *testing.T) {
	obfsKey := []byte("psiphon-obfuscation-key")

	// 1. Seeded randomized profile, persisted and replayed.
	seed, err := NewPRNGSeed()
	if err != nil {
		t.Fatal(err)
	}
	stored := hex.EncodeToString(seed[:]) // e.g. kept in the server entry / tactics
	var replayed [32]byte
	if d, err := hex.DecodeString(stored); err != nil || copy(replayed[:], d) != 32 {
		t.Fatal("seed did not round-trip")
	}
	a, _ := SeededRandomized(seed, &DefaultWeights).Spec()
	b, _ := SeededRandomized(replayed, &DefaultWeights).Spec()
	j1, _, _ := JA3(renderHello(t, CustomFingerprint("A", "1", func() (*ClientHelloSpec, error) { return a.Clone(), nil }), "utls.test"))
	j2, _, _ := JA3(renderHello(t, CustomFingerprint("B", "1", func() (*ClientHelloSpec, error) { return b.Clone(), nil }), "utls.test"))
	if j1 != j2 {
		t.Fatal("replayed seed produced a different fingerprint")
	}

	// 2+3+4. Passthrough random, obfuscated TLS 1.2 session ticket and
	// ClientHello fragmentation, on one connection.
	scfg := serverConfig(t)
	scfg.MaxVersion = tls.VersionTLS12
	var ticketKey [32]byte
	copy(ticketKey[:], sha256.New().Sum(obfsKey)) // both sides derive it from the obfuscation key
	scfg.SetSessionTicketKeys([][32]byte{ticketKey})

	secret := make([]byte, 48)
	rand.Read(secret)
	suite := tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	ss, err := tls.ParseSessionState(serverSessionBytes(suite, secret, tls.X25519))
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := scfg.EncryptTicket(tls.ConnectionState{}, ss)
	if err != nil {
		t.Fatal(err)
	}

	var first [][]byte
	addr, serr := serveOnce(t, func(c net.Conn, h *peekedHello) error {
		if !passthroughVerify(obfsKey, h.random) {
			return errors.New("passthrough: client random does not authenticate")
		}
		s := tls.Server(replay(c, h.record), scfg)
		if err := s.Handshake(); err != nil {
			return err
		}
		if !s.ConnectionState().DidResume {
			return errors.New("obfuscated session ticket not resumed")
		}
		return nil
	})
	raw, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	wc := &writesConn{Conn: raw}
	// Psiphon's server certificate is verified out of band (pinned); here,
	// the test CA.
	uc := UClient(wc, clientConfig(t), HelloChrome_Auto)
	if err := uc.SetClientHelloHook(passthroughHook(obfsKey)); err != nil {
		t.Fatal(err)
	}
	if err := uc.SetSessionParams(ClientSessionParams{
		Version: tls.VersionTLS12, CipherSuite: suite, Secret: secret, Ticket: ticket, ExtendedMasterSecret: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := uc.SetFragmentation(FragmentOptions{Records: true, SplitAtSNI: true}); err != nil {
		t.Fatal(err)
	}
	if err := uc.Handshake(); err != nil {
		t.Fatalf("client: %v (server: %v)", err, <-serr)
	}
	if err := <-serr; err != nil {
		t.Fatal(err)
	}
	if !uc.ConnectionState().DidResume {
		t.Fatal("client did not resume the obfuscated session")
	}
	first = wc.all()
	if n := len(records(t, first[0])); n != 2 {
		t.Fatalf("ClientHello in %d records, want 2 (split at SNI)", n)
	}
}

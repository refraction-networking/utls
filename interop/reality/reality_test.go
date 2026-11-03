// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reality

// The uTLS v2 client against the real XTLS/REALITY server, at the revision
// Xray-core pins (github.com/xtls/reality v0.0.0-20261014101318-83f621788ca8).
// The client side reproduces Xray's REALITY client
// (transport/internet/reality/reality.go) with the v2 API:
//
//   - session ID = AES-GCM(authKey, nonce=Random[20:], aad=ClientHello with a
//     zeroed session ID) of {version, 0, unix time, short ID}, where authKey =
//     HKDF-SHA256(X25519(ephemeral, server public key), salt=Random[:20],
//     info="REALITY"), written by the ClientHello hook;
//   - server authentication: the leaf is an Ed25519 certificate whose
//     signature field is HMAC-SHA512(authKey, Ed25519 public key); with an
//     ML-DSA-65 verify key, the leaf's first extension must also carry
//     ML-DSA-65(HMAC(authKey, pub || ClientHello || ServerHello)).
//
// The server forces an Ed25519 CertificateVerify, which a Chrome hello does
// not advertise; the uTLS client accepts it exactly as crypto/tls does
// (RFC 8446 4.4.3 checks against the client's supported algorithms).
// Unauthenticated clients are forwarded to a local "cover" TLS server.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls/v2"
	"github.com/xtls/reality"
)

const serverName = "cover.example"

// coverServer is the "dest" REALITY forwards unauthenticated clients to: an
// ordinary TLS 1.3 server with an ECDSA certificate that echoes one line.
func coverServer(t *testing.T) (string, *atomic.Int32) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// Real covers are large sites whose certificate records are several KB;
	// REALITY pads its own (ML-DSA-65 certificates are ~4 KB) to the cover's
	// record sizes, so the cover's leaf carries many SANs, like a CDN's.
	names := []string{serverName}
	for i := range 250 {
		names = append(names, fmt.Sprintf("alt%03d.%s", i, serverName))
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: serverName},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var served atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				if err := c.(*tls.Conn).Handshake(); err != nil {
					return
				}
				served.Add(1)
				b := make([]byte, 4)
				if _, err := io.ReadFull(c, b); err == nil {
					c.Write([]byte("cover"))
				}
			}(c)
		}
	}()
	return ln.Addr().String(), &served
}

type realityServer struct {
	addr     string
	pub      []byte
	shortID  [8]byte
	mldsaPub *mldsa.PublicKey
	accepted chan error // per connection: nil if the REALITY handshake and echo succeeded
}

func startReality(t *testing.T, cover string, withMLDSA bool) *realityServer {
	t.Helper()
	priv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	rs := &realityServer{pub: priv.PublicKey().Bytes(), shortID: [8]byte{0x0a, 0x1b, 0x2c, 0x3d}, accepted: make(chan error, 8)}
	cfg := &reality.Config{
		DialContext:            (&net.Dialer{}).DialContext,
		Type:                   "tcp",
		Dest:                   cover,
		ServerNames:            map[string]bool{serverName: true},
		PrivateKey:             priv,
		MaxTimeDiff:            time.Minute,
		ShortIds:               map[[8]byte]bool{rs.shortID: true},
		SessionTicketsDisabled: true,
		NextProtos:             []string{"h2", "http/1.1"},
	}
	if withMLDSA {
		seed := make([]byte, 32)
		rand.Read(seed)
		k, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Mldsa65Key = k
		cfg.Show = os.Getenv("REALITY_SHOW") != ""
		rs.mldsaPub = k.PublicKey()
	}
	// As Xray does at startup: learn the cover's post-handshake record
	// lengths (the server mimics them and waits until they are known).
	reality.DetectPostHandshakeRecordsLens(cfg)
	deadline := time.Now().Add(10 * time.Second)
	for alpn := range 3 {
		key := cover + " " + serverName + " " + string(rune('0'+alpn))
		for {
			if v, ok := reality.GlobalPostHandshakeRecordsLens.Load(key); ok {
				if _, done := v.([]int); done {
					break
				}
			}
			if time.Now().After(deadline) {
				t.Fatalf("post-handshake record detection for %q did not finish", key)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	rs.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				c.SetDeadline(time.Now().Add(5 * time.Second))
				rc, err := reality.Server(context.Background(), c, cfg)
				if err != nil {
					rs.accepted <- err
					return
				}
				defer rc.Close()
				b := make([]byte, 4)
				if _, err := io.ReadFull(rc, b); err != nil {
					rs.accepted <- err
					return
				}
				_, err = rc.Write(append([]byte("reality:"), b...))
				rs.accepted <- err
			}(c)
		}
	}()
	return rs
}

// clientOpts are the knobs of the Xray-style client used by the cases.
type clientOpts struct {
	id        utls.ClientHelloID
	serverPub []byte
	shortID   [8]byte
	clock     time.Time
	mldsaPub  *mldsa.PublicKey
	authKeyBy *utls.CurveID // which offered key the client derives authKey from
}

type realityClient struct {
	uc       *utls.UConn
	authKey  []byte
	verified bool
}

func dialReality(t *testing.T, addr string, o clientOpts) (*realityClient, error) {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	rc := &realityClient{}
	cfg := &tls.Config{
		ServerName:             serverName,
		SessionTicketsDisabled: true, // the AEAD covers the whole hello: no PSK binders
		InsecureSkipVerify:     true, // authenticated below, as Xray does
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pub, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok || rc.authKey == nil {
				return errors.New("reality: not a REALITY certificate")
			}
			h := hmac.New(sha512.New, rc.authKey)
			h.Write(pub)
			if !bytes.Equal(h.Sum(nil), cert.Signature) {
				return errors.New("reality: certificate HMAC mismatch")
			}
			if o.mldsaPub != nil {
				if len(cert.Extensions) == 0 {
					return errors.New("reality: no ML-DSA-65 extension")
				}
				h.Write(rc.uc.ClientHelloRaw())
				h.Write(rc.uc.ServerHelloRaw())
				if err := mldsa.Verify(o.mldsaPub, h.Sum(nil), cert.Extensions[0].Value, nil); err != nil {
					return errors.New("reality: ML-DSA-65 verification failed: " + err.Error())
				}
			}
			rc.verified = true
			return nil
		},
	}
	rc.uc = utls.UClient(conn, cfg, o.id)
	err = rc.uc.SetClientHelloHook(func(h *utls.ClientHelloContext) error {
		if h.PSK {
			return errors.New("reality: resumption must be disabled")
		}
		group := utls.X25519
		if o.authKeyBy != nil {
			group = *o.authKeyBy
		}
		priv := h.EphemeralKey(group)
		if priv == nil {
			return errors.New("reality: no ephemeral key for the chosen group")
		}
		peer, err := ecdh.X25519().NewPublicKey(o.serverPub)
		if err != nil {
			return err
		}
		shared, err := priv.ECDH(peer)
		if err != nil {
			return err
		}
		if rc.authKey, err = hkdf.Key(sha256.New, shared, h.Random[:20], "REALITY", 32); err != nil {
			return err
		}
		var plain [16]byte
		plain[0], plain[1], plain[2] = 26, 1, 0 // client version
		binary.BigEndian.PutUint32(plain[4:], uint32(o.clock.Unix()))
		copy(plain[8:], o.shortID[:])
		block, _ := aes.NewCipher(rc.authKey)
		aead, _ := cipher.NewGCM(block)
		aad := bytes.Clone(h.Raw)
		clear(aad[39 : 39+32])
		copy(h.SessionID, aead.Seal(nil, h.Random[20:], plain[:], aad))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return rc, rc.uc.Handshake()
}

func exchange(t *testing.T, rc *realityClient) string {
	t.Helper()
	if _, err := rc.uc.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 64)
	n, err := io.ReadAtLeast(rc.uc, b, 5)
	if err != nil {
		t.Fatal(err)
	}
	return string(b[:n])
}

// hybridOnly is Chrome without the separate X25519 key share: REALITY must
// then use the X25519 half of X25519MLKEM768 (its "secondary choice").
func hybridOnly() (*utls.ClientHelloSpec, error) {
	s, err := utls.HelloChrome_156.Spec()
	if err != nil {
		return nil, err
	}
	for _, e := range s.Extensions {
		if ks, ok := e.(*utls.KeyShareExtension); ok {
			ks.KeyShares = slices.DeleteFunc(ks.KeyShares, func(k utls.KeyShareEntry) bool { return k.Group == utls.X25519 })
		}
	}
	return s, nil
}

func noHybrid() (*utls.ClientHelloSpec, error) {
	s, err := utls.HelloChrome_156.Spec()
	if err != nil {
		return nil, err
	}
	for _, e := range s.Extensions {
		switch e := e.(type) {
		case *utls.KeyShareExtension:
			e.KeyShares = slices.DeleteFunc(e.KeyShares, func(k utls.KeyShareEntry) bool { return k.Group == utls.X25519MLKEM768 })
		case *utls.SupportedCurvesExtension:
			e.Curves = slices.DeleteFunc(e.Curves, func(c utls.CurveID) bool { return c == utls.X25519MLKEM768 })
		}
	}
	return s, nil
}

func TestREALITYAuthenticated(t *testing.T) {
	hybrid := utls.X25519MLKEM768
	for _, tc := range []struct {
		name      string
		id        utls.ClientHelloID
		authKeyBy *utls.CurveID
		mldsa     bool
	}{
		// Chrome: separate X25519 share; REALITY authenticates with it.
		{"chrome156 X25519 share", utls.HelloChrome_156, nil, false},
		// Firefox: the X25519 share is the hybrid's X25519 half.
		{"firefox158 reused share", utls.HelloFirefox_158, nil, false},
		// Only X25519MLKEM768 offered: authKey from the hybrid's X25519 half.
		{"hybrid share only", utls.CustomFingerprint("Chrome", "hybrid-only", hybridOnly), &hybrid, false},
		// ML-DSA-65 extra server authentication.
		{"chrome156 ML-DSA-65", utls.HelloChrome_156, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cover, coverServed := coverServer(t)
			rs := startReality(t, cover, tc.mldsa)
			o := clientOpts{id: tc.id, serverPub: rs.pub, shortID: rs.shortID, clock: time.Now(), authKeyBy: tc.authKeyBy}
			if tc.mldsa {
				o.mldsaPub = rs.mldsaPub
			}
			rc, err := dialReality(t, rs.addr, o)
			if err != nil {
				t.Fatalf("handshake: %v", err)
			}
			if !rc.verified {
				t.Fatal("REALITY certificate not verified")
			}
			if got := exchange(t, rc); got != "reality:ping" {
				t.Fatalf("application data %q", got)
			}
			if err := <-rs.accepted; err != nil {
				t.Fatalf("server: %v", err)
			}
			st := rc.uc.ConnectionState()
			// The TLS key exchange itself uses the hybrid group REALITY selects.
			if st.Version != tls.VersionTLS13 || st.CurveID != tls.X25519MLKEM768 {
				t.Fatalf("version %x curve %v", st.Version, st.CurveID)
			}
			if n := coverServed.Load(); n != 0 {
				t.Fatalf("authenticated client was forwarded to the cover %d times", n)
			}
		})
	}
}

// Every authentication failure is forwarded to the cover server; the uTLS
// client then sees the cover's ordinary certificate and refuses it, so no
// application data reaches an impostor.
func TestREALITYRejected(t *testing.T) {
	otherKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	wrongMLDSA, _ := mldsa.NewPrivateKey(mldsa.MLDSA65(), make([]byte, 32))
	for _, tc := range []struct {
		name  string
		mod   func(o *clientOpts, rs *realityServer)
		mldsa bool
		cover bool // forwarded to the cover (vs. the REALITY handshake itself failing)
	}{
		{"wrong server public key", func(o *clientOpts, _ *realityServer) { o.serverPub = otherKey.PublicKey().Bytes() }, false, true},
		{"unknown short ID", func(o *clientOpts, _ *realityServer) { o.shortID = [8]byte{9, 9, 9} }, false, true},
		{"stale timestamp", func(o *clientOpts, _ *realityServer) { o.clock = time.Now().Add(-10 * time.Minute) }, false, true},
		{"no X25519MLKEM768", func(o *clientOpts, _ *realityServer) {
			o.id = utls.CustomFingerprint("Chrome", "no-pq", noHybrid)
		}, false, true},
		{"wrong ML-DSA-65 key", func(o *clientOpts, _ *realityServer) { o.mldsaPub = wrongMLDSA.PublicKey() }, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cover, coverServed := coverServer(t)
			rs := startReality(t, cover, tc.mldsa)
			o := clientOpts{id: utls.HelloChrome_156, serverPub: rs.pub, shortID: rs.shortID, clock: time.Now(), mldsaPub: rs.mldsaPub}
			tc.mod(&o, rs)
			rc, err := dialReality(t, rs.addr, o)
			if err == nil || rc.verified {
				t.Fatalf("handshake succeeded (verified=%v)", rc.verified)
			}
			if tc.cover {
				if !bytes.Contains([]byte(err.Error()), []byte("not a REALITY certificate")) {
					t.Fatalf("error %v, want the cover's certificate to be refused", err)
				}
			} else if !bytes.Contains([]byte(err.Error()), []byte("ML-DSA-65")) {
				t.Fatalf("error %v", err)
			}
			if tc.cover && coverServed.Load() != 0 {
				t.Fatal("cover completed a handshake the client should have aborted")
			}
		})
	}
}

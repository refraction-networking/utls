// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// testPKI is a CA plus a leaf for "utls.test", "127.0.0.1" and "::1".
type testPKI struct {
	roots *x509.CertPool
	cert  tls.Certificate
}

var (
	pkiOnce sync.Once
	pki     testPKI
)

func getPKI(t testing.TB) testPKI {
	pkiOnce.Do(func() {
		caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "uTLS test CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDER, _ := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
		caCert, _ := x509.ParseCertificate(caDER)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "utls.test"},
			DNSNames: []string{"utls.test", "secret.example", "public.example"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
		der, _ := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
		pki.roots = x509.NewCertPool()
		pki.roots.AddCert(caCert)
		pki.cert = tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	})
	return pki
}

func serverConfig(t testing.TB) *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{getPKI(t).cert}, NextProtos: []string{"h2", "http/1.1"}}
}

func clientConfig(t testing.TB) *tls.Config {
	return &tls.Config{ServerName: "utls.test", RootCAs: getPKI(t).roots}
}

// recConn records bytes written by the client.
type recConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recConn) Write(b []byte) (int, error) {
	r.mu.Lock()
	r.buf.Write(b)
	r.mu.Unlock()
	return r.Conn.Write(b)
}

func (r *recConn) written() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}

// firstRecord returns the first TLS record written (the ClientHello).
func (r *recConn) firstRecord() []byte {
	b := r.written()
	if len(b) < 5 {
		return nil
	}
	n := 5 + (int(b[3])<<8 | int(b[4]))
	if len(b) < n {
		return nil
	}
	return b[:n]
}

type hsResult struct {
	uc         *UConn
	rec        *recConn
	cerr, serr error
	sstate     tls.ConnectionState
}

// handshakeStd runs a uTLS client against a stdlib server over loopback and
// exchanges one byte each way (so TLS 1.3 tickets arrive).
func handshakeStd(t testing.TB, id ClientHelloID, ccfg, scfg *tls.Config, setup func(*UConn)) *hsResult {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	type sres struct {
		err error
		st  tls.ConnectionState
	}
	done := make(chan sres, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- sres{err: err}
			return
		}
		c.SetDeadline(time.Now().Add(20 * time.Second))
		s := tls.Server(c, scfg)
		err = s.Handshake()
		if err == nil {
			b := make([]byte, 1)
			if _, err = io.ReadFull(s, b); err == nil {
				_, err = s.Write([]byte("s"))
			}
		}
		done <- sres{err, s.ConnectionState()}
		s.Close()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(20 * time.Second))
	rec := &recConn{Conn: raw}
	uc := UClient(rec, ccfg, id)
	if setup != nil {
		setup(uc)
	}
	r := &hsResult{uc: uc, rec: rec}
	r.cerr = uc.Handshake()
	if r.cerr == nil {
		if _, err := uc.Write([]byte("c")); err != nil {
			r.cerr = err
		} else {
			b := make([]byte, 1)
			_, r.cerr = io.ReadFull(uc, b)
		}
	}
	if r.cerr != nil {
		raw.Close()
	}
	s := <-done
	r.serr, r.sstate = s.err, s.st
	uc.Close()
	return r
}

func (r *hsResult) ok(t testing.TB) {
	t.Helper()
	if r.cerr != nil || r.serr != nil {
		t.Fatalf("handshake failed: client=%v server=%v", r.cerr, r.serr)
	}
}

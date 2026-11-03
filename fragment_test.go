// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// writesConn records each Write separately.
type writesConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
}

func (w *writesConn) Write(b []byte) (int, error) {
	w.mu.Lock()
	w.writes = append(w.writes, bytes.Clone(b))
	w.mu.Unlock()
	return w.Conn.Write(b)
}

func (w *writesConn) all() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.writes...)
}

// records splits a byte stream into TLS records.
func records(t *testing.T, b []byte) [][]byte {
	t.Helper()
	var out [][]byte
	for len(b) > 0 {
		if len(b) < 5 {
			t.Fatalf("truncated record header")
		}
		n := 5 + (int(b[3])<<8 | int(b[4]))
		if len(b) < n {
			t.Fatalf("truncated record")
		}
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}

// fragHandshake runs a handshake against crypto/tls with fragmentation o and
// returns the client's writes (first ClientHello flight first).
func fragHandshake(t *testing.T, id ClientHelloID, ccfg, scfg *tls.Config, o FragmentOptions) ([][]byte, error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			serr <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(10 * time.Second))
		serr <- tls.Server(c, scfg).Handshake()
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(10 * time.Second))
	wc := &writesConn{Conn: raw}
	uc := UClient(wc, ccfg, id)
	if err := uc.SetFragmentation(o); err != nil {
		t.Fatal(err)
	}
	cerr := uc.Handshake()
	if cerr == nil {
		cerr = <-serr
	}
	return wc.all(), cerr
}

func TestFragmentRecordsAtSNI(t *testing.T) {
	for _, id := range []ClientHelloID{HelloChrome_Auto, HelloFirefox_Auto, HelloGolang} {
		writes, err := fragHandshake(t, id, clientConfig(t), serverConfig(t), FragmentOptions{Records: true, SplitAtSNI: true})
		if err != nil {
			t.Fatalf("%s: %v", id.Str(), err)
		}
		recs := records(t, writes[0])
		if len(recs) != 2 {
			t.Fatalf("%s: %d records in the first write, want 2", id.Str(), len(recs))
		}
		host := []byte("utls.test")
		joined := append(bytes.Clone(recs[0][5:]), recs[1][5:]...)
		if bytes.Contains(recs[0], host) || bytes.Contains(recs[1], host) || !bytes.Contains(joined, host) {
			t.Fatalf("%s: SNI not split across records", id.Str())
		}
		if !bytes.HasSuffix(recs[0], []byte("utls")) || !bytes.HasPrefix(recs[1][5:], []byte(".test")) {
			t.Fatalf("%s: split not at the host midpoint: %q | %q", id.Str(), recs[0][len(recs[0])-8:], recs[1][5:13])
		}
	}
}

func TestFragmentSegments(t *testing.T) {
	writes, err := fragHandshake(t, HelloChrome_Auto, clientConfig(t), serverConfig(t),
		FragmentOptions{Segments: true, SplitAtSNI: true, Delay: 5 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if len(writes) < 3 {
		t.Fatalf("%d writes", len(writes))
	}
	// Two writes that together form exactly one record.
	first := append(bytes.Clone(writes[0]), writes[1]...)
	if recs := records(t, first); len(recs) != 1 || recs[0][5] != 1 {
		t.Fatal("segments do not form one ClientHello record")
	}
	if bytes.Contains(writes[0], []byte("utls.test")) || bytes.Contains(writes[1], []byte("utls.test")) {
		t.Fatal("SNI not split across writes")
	}
}

func TestFragmentRecordsSegmentsMaxSize(t *testing.T) {
	writes, err := fragHandshake(t, HelloChrome_Auto, clientConfig(t), serverConfig(t),
		FragmentOptions{Records: true, Segments: true, SplitAtSNI: true, MaxPieceSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	var hello []byte
	n := 0
	for _, w := range writes {
		recs := records(t, w)
		if len(recs) != 1 || recs[0][0] != 22 {
			break
		}
		if len(recs[0])-5 > 100 {
			t.Fatalf("record payload %d > 100", len(recs[0])-5)
		}
		hello = append(hello, recs[0][5:]...)
		n++
		if len(hello) >= 4 && len(hello) == 4+(int(hello[1])<<16|int(hello[2])<<8|int(hello[3])) {
			break
		}
	}
	if n < 15 || hello[0] != 1 {
		t.Fatalf("expected many single-record writes, got %d", n)
	}
}

func TestFragmentErrors(t *testing.T) {
	c1, _ := net.Pipe()
	uc := UClient(c1, clientConfig(t), HelloChrome_Auto)
	for _, bad := range []FragmentOptions{
		{}, {Records: true}, {SplitAtSNI: true}, {Records: true, MaxPieceSize: -1},
		{Records: true, SplitAtSNI: true, Delay: time.Millisecond},
		{Segments: true, SplitAtSNI: true, Delay: 2 * time.Second},
	} {
		if err := uc.SetFragmentation(bad); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
	// SplitAtSNI with an IP address: fails before anything is written.
	cfg := clientConfig(t)
	cfg.ServerName = "127.0.0.1"
	c2, c3 := net.Pipe()
	defer c3.Close()
	rec := &recConn{Conn: c2}
	uc = UClient(rec, cfg, HelloChrome_Auto)
	if err := uc.SetFragmentation(FragmentOptions{Records: true, SplitAtSNI: true}); err != nil {
		t.Fatal(err)
	}
	if err := uc.Handshake(); err == nil || !strings.Contains(err.Error(), "server_name") {
		t.Fatalf("err = %v", err)
	}
	if len(rec.written()) != 0 {
		t.Fatal("bytes written despite the fragmentation error")
	}
	// After the handshake, it is rejected.
	r := handshakeStd(t, HelloChrome_Auto, clientConfig(t), serverConfig(t), nil)
	r.ok(t)
	if err := r.uc.SetFragmentation(FragmentOptions{Records: true, SplitAtSNI: true}); err == nil {
		t.Fatal("SetFragmentation after the handshake accepted")
	}
}

func TestFragmentOnlyFirstHello(t *testing.T) {
	scfg := serverConfig(t)
	scfg.CurvePreferences = []tls.CurveID{tls.CurveP384} // forces HelloRetryRequest
	writes, err := fragHandshake(t, HelloChrome_Auto, clientConfig(t), scfg, FragmentOptions{Records: true, SplitAtSNI: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(records(t, writes[0])) != 2 {
		t.Fatal("first hello not fragmented")
	}
	// The second ClientHello (after CCS) goes out in a single record.
	for _, w := range writes[1:] {
		for _, r := range records(t, w) {
			if r[0] == 22 && r[5] == 1 && len(r) < 200 {
				t.Fatal("second ClientHello fragmented")
			}
		}
	}
}

func TestFragmentDialerOption(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan int, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- -1
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		// Count records until the ClientHello is complete.
		var msg []byte
		n := 0
		for len(msg) < 4 || len(msg) < 4+(int(msg[1])<<16|int(msg[2])<<8|int(msg[3])) {
			hdr := make([]byte, 5)
			if _, err := io.ReadFull(c, hdr); err != nil {
				got <- -1
				return
			}
			b := make([]byte, int(hdr[3])<<8|int(hdr[4]))
			io.ReadFull(c, b)
			msg = append(msg, b...)
			n++
		}
		got <- n
	}()
	d := &Dialer{Config: clientConfig(t), Fragmentation: &FragmentOptions{Records: true, SplitAtSNI: true}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	d.DialContext(ctx, "tcp", ln.Addr().String()) // server never answers
	if n := <-got; n != 2 {
		t.Fatalf("Dialer: ClientHello in %d records, want 2", n)
	}
	bad := &Dialer{Config: clientConfig(t), Fragmentation: &FragmentOptions{}}
	if _, err := bad.DialContext(ctx, "tcp", ln.Addr().String()); err == nil {
		t.Fatal("invalid Dialer fragmentation accepted")
	}
}

// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls_test

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"time"

	utls "github.com/refraction-networking/utls/v2"
)

func ExampleDialContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := utls.DialContext(ctx, "tcp", "example.com:443",
		&tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	st := conn.ConnectionState() // a standard crypto/tls.ConnectionState
	fmt.Println(tls.VersionName(st.Version), st.NegotiatedProtocol)
}

func ExampleDialer() {
	// A Dialer returns handshaken TLS connections as net.Conn, for any
	// protocol stack that accepts a dial function (gRPC, HTTP clients, ...).
	// The caller's stack owns application behavior: uTLS negotiates TLS,
	// ALPN and (opaque) ALPS bytes only.
	d := &utls.Dialer{Config: &tls.Config{NextProtos: []string{"http/1.1"}}, ClientHelloID: utls.HelloChrome_Auto}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()
	uc := c.(*utls.UConn)
	st := uc.ConnectionState() // standard crypto/tls.ConnectionState
	fmt.Println(st.NegotiatedProtocol)
	if settings, ok := uc.NegotiatedApplicationSettings(); ok {
		_ = settings // ALPS: the peer's application settings, for the caller's protocol stack
	}
}

func ExampleParseFingerprint() {
	id, err := utls.ParseFingerprint("safari")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(id.Str())
	// Output: Safari-Auto
}

func ExampleUConn_SetClientHelloHook() {
	uc := utls.UClient(dialTCP(), &tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	err := uc.SetClientHelloHook(func(h *utls.ClientHelloContext) error {
		// h.Raw is the final ClientHello; h.Random and h.SessionID may be
		// overwritten in place; h.EphemeralKey gives the offered ECDH keys.
		key := h.EphemeralKey(utls.X25519)
		_ = key
		copy(h.SessionID, []byte("authenticator..."))
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	if err := uc.Handshake(); err != nil {
		log.Fatal(err)
	}
}

func ExampleUConn_SetFragmentation() {
	uc := utls.UClient(dialTCP(), &tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	// Two TLS records, split inside the SNI host name, sent as two writes.
	if err := uc.SetFragmentation(utls.FragmentOptions{Records: true, Segments: true, SplitAtSNI: true}); err != nil {
		log.Fatal(err)
	}
	if err := uc.Handshake(); err != nil {
		log.Fatal(err)
	}
}

func ExampleUConn_HandOff() {
	uc := utls.UClient(dialTCP(), &tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
	if err := uc.Handshake(); err != nil {
		log.Fatal(err)
	}
	st, err := uc.HandOff() // TLS 1.3 only
	if err != nil {
		log.Fatal(err)
	}
	// Install st.WriteKey/WriteIV/WriteSeq and st.ReadKey/ReadIV/ReadSeq in
	// kernel TLS, or run your own record layer over st.Conn. Deliver
	// st.Plaintext first, then decrypt st.RawInput.
	_ = st
}

func ExampleParseProfile() {
	p, err := utls.ExportProfile(utls.HelloFirefox_158)
	if err != nil {
		log.Fatal(err)
	}
	data, _ := p.MarshalJSON() // versioned JSON: ship it, store it, edit it
	q, err := utls.ParseProfile(data)
	if err != nil {
		log.Fatal(err)
	}
	id := q.ClientHelloID()
	fmt.Println(id.Client, id.Version)
	// Output: Firefox 158
}

func ExampleQUICClient() {
	q := utls.QUICClient(&tls.QUICConfig{TLSConfig: &tls.Config{
		ServerName: "example.com", MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"},
	}}, utls.HelloChrome_Auto)
	q.SetTransportParameters(encodedTransportParameters())
	if err := q.Start(context.Background()); err != nil {
		log.Fatal(err)
	}
	for e := q.NextEvent(); e.Kind != tls.QUICNoEvent; e = q.NextEvent() {
		_ = e // hand QUICWriteData to the QUIC stack, install secrets, ...
	}
}

// conn stands for any established net.Conn (examples without Output are only
// compiled, not run).
var conn net.Conn

func dialTCP() net.Conn                  { return conn }
func encodedTransportParameters() []byte { return []byte{} }

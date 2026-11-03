// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"testing"
)

// quicSide abstracts the client (uTLS) and server (crypto/tls) QUIC conns.
type quicSide interface {
	NextEvent() tls.QUICEvent
	HandleData(tls.QUICEncryptionLevel, []byte) error
	SetTransportParameters([]byte)
}

type quicPeer struct {
	conn      quicSide
	gotParams []byte
	complete  bool
	onStore   func(*tls.SessionState)
	onResume  func(*tls.SessionState)
	early     bool // saw an Early write secret
}

// runQUIC shuttles CRYPTO data between client and server until both finish.
func runQUIC(t *testing.T, cli, srv *quicPeer) error {
	t.Helper()
	for i := 0; i < 100 && !(cli.complete && srv.complete); i++ {
		progressed := false
		for _, p := range []struct{ from, to *quicPeer }{{cli, srv}, {srv, cli}} {
			for {
				e := p.from.conn.NextEvent()
				if e.Kind == tls.QUICNoEvent {
					break
				}
				progressed = true
				switch e.Kind {
				case tls.QUICWriteData:
					if err := p.to.conn.HandleData(e.Level, bytes.Clone(e.Data)); err != nil {
						return err
					}
				case tls.QUICTransportParameters:
					p.from.gotParams = bytes.Clone(e.Data)
				case tls.QUICTransportParametersRequired:
					p.from.conn.SetTransportParameters([]byte("srv-params"))
				case tls.QUICHandshakeDone:
					p.from.complete = true
				case tls.QUICStoreSession:
					if p.from.onStore != nil {
						p.from.onStore(e.SessionState)
					}
				case tls.QUICResumeSession:
					if p.from.onResume != nil {
						p.from.onResume(e.SessionState)
					}
				case tls.QUICSetWriteSecret:
					if e.Level == tls.QUICEncryptionLevelEarly {
						p.from.early = true
					}
				case tls.QUICErrorEvent:
					return e.Err
				}
			}
		}
		if !progressed {
			return errors.New("QUIC handshake stalled")
		}
	}
	return nil
}

func quicServer(t *testing.T, scfg *tls.Config) *tls.QUICConn {
	s := tls.QUICServer(&tls.QUICConfig{TLSConfig: scfg, EnableSessionEvents: true})
	s.SetTransportParameters([]byte("srv-params"))
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

// quicChromeSpec is a TLS-1.3-only spec with a transport parameters slot.
func quicChromeSpec() (*ClientHelloSpec, error) {
	s, err := HelloChrome_155.Spec()
	if err != nil {
		return nil, err
	}
	for i, e := range s.Extensions {
		if v, ok := e.(*SupportedVersionsExtension); ok {
			v.Versions = []uint16{GREASE_PLACEHOLDER, VersionTLS13}
		}
		if _, ok := e.(*SessionTicketExtension); ok {
			s.Extensions[i] = &QUICTransportParametersExtension{}
		}
	}
	s.TLSVersMin = VersionTLS13
	return s, nil
}

func TestQUICClientHandshake(t *testing.T) {
	quicID := CustomFingerprint("ChromeQUIC", "test", quicChromeSpec)
	for _, id := range []ClientHelloID{quicID, HelloGolang} {
		t.Run(id.Str(), func(t *testing.T) {
			cache := tls.NewLRUClientSessionCache(4)
			ccfg := clientConfig(t)
			ccfg.MinVersion = tls.VersionTLS13
			ccfg.NextProtos = []string{"h3"}
			ccfg.ClientSessionCache = cache
			c := QUICClient(&tls.QUICConfig{TLSConfig: ccfg, EnableSessionEvents: true}, id)
			c.SetTransportParameters([]byte("cli-params"))
			if err := c.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			scfg := serverConfig(t) // shared: same ticket keys for resumption
			scfg.MinVersion = tls.VersionTLS13
			scfg.NextProtos = []string{"h3"}
			s := quicServer(t, scfg)
			stored := 0
			cli := &quicPeer{conn: c, onStore: func(ss *tls.SessionState) {
				if ss == nil {
					t.Error("nil session in QUICStoreSession")
					return
				}
				ss.Extra = append(ss.Extra, []byte("quic-app-state"))
				ss.EarlyData = true
				if err := c.StoreSession(ss); err != nil {
					t.Error(err)
				}
				stored++
			}}
			srv := &quicPeer{conn: s}
			if err := runQUIC(t, cli, srv); err != nil {
				t.Fatal(err)
			}
			if string(cli.gotParams) != "srv-params" || string(srv.gotParams) != "cli-params" {
				t.Fatalf("transport params %q / %q", cli.gotParams, srv.gotParams)
			}
			st := c.ConnectionState()
			if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "h3" || len(st.PeerCertificates) == 0 {
				t.Fatalf("state %+v", st)
			}
			if id == quicID {
				h := parseHelloFields(t, c.ClientHelloRaw())
				if h.extIDs[len(h.extIDs)-1] == 57 || !contains(h.extIDs, 57) {
					t.Fatalf("transport parameters not in the spec slot: %v", h.extIDs)
				}
			}
			// The server sends a ticket after the handshake; feed it.
			for e := s.NextEvent(); e.Kind != tls.QUICNoEvent; e = s.NextEvent() {
				if e.Kind == tls.QUICWriteData {
					if err := c.HandleData(e.Level, e.Data); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := s.SendSessionTicket(tls.QUICSessionTicketOptions{EarlyData: true}); err != nil {
				t.Fatal(err)
			}
			for e := s.NextEvent(); e.Kind != tls.QUICNoEvent; e = s.NextEvent() {
				if e.Kind == tls.QUICWriteData {
					if err := c.HandleData(e.Level, e.Data); err != nil {
						t.Fatal(err)
					}
				}
			}
			for e := c.NextEvent(); e.Kind != tls.QUICNoEvent; e = c.NextEvent() {
				if e.Kind == tls.QUICStoreSession {
					cli.onStore(e.SessionState)
				}
			}
			if stored == 0 {
				t.Fatal("no QUICStoreSession")
			}

			// Resume: the session (with the app's Extra) comes back.
			c2 := QUICClient(&tls.QUICConfig{TLSConfig: ccfg, EnableSessionEvents: true}, id)
			c2.SetTransportParameters([]byte("cli-params"))
			if err := c2.Start(context.Background()); err != nil {
				t.Fatal(err)
			}
			var resumed *tls.SessionState
			cli2 := &quicPeer{conn: c2, onResume: func(ss *tls.SessionState) { resumed = ss }}
			srv2 := &quicPeer{conn: quicServer(t, scfg)}
			if err := runQUIC(t, cli2, srv2); err != nil {
				t.Fatal(err)
			}
			if resumed == nil || len(resumed.Extra) == 0 || string(resumed.Extra[len(resumed.Extra)-1]) != "quic-app-state" {
				t.Fatalf("resumed session %+v", resumed)
			}
			if !c2.ConnectionState().DidResume {
				t.Fatal("did not resume")
			}
			if !cli2.early {
				t.Fatal("0-RTT write secret not offered for an EarlyData session")
			}
		})
	}
}

func TestQUICClientErrors(t *testing.T) {
	if err := QUICClient(nil, HelloChrome_Auto).Start(context.Background()); err == nil {
		t.Fatal("nil config accepted")
	}
	ccfg := clientConfig(t)
	ccfg.MinVersion = tls.VersionTLS13
	c := QUICClient(&tls.QUICConfig{TLSConfig: ccfg}, HelloCustom)
	c.SetTransportParameters(nil)
	err := c.Start(context.Background())
	for e := c.NextEvent(); err == nil && e.Kind != tls.QUICNoEvent; e = c.NextEvent() {
		err = e.Err
	}
	if !errors.Is(err, ErrNoSpec) {
		t.Fatalf("HelloCustom without spec: %v", err)
	}
	if ae := (tls.AlertError(0)); !errors.As(err, &ae) {
		t.Fatalf("QUIC error does not wrap tls.AlertError: %T", err)
	}
	bad := CustomFingerprint("Broken", "1", func() (*ClientHelloSpec, error) { return nil, errors.New("boom") })
	if err := QUICClient(&tls.QUICConfig{TLSConfig: ccfg}, bad).Start(context.Background()); err == nil {
		t.Fatal("broken factory accepted by Start")
	}
	if err := QUICClient(&tls.QUICConfig{TLSConfig: ccfg}, HelloChrome_Auto).SendSessionTicket(tls.QUICSessionTicketOptions{}); err == nil {
		t.Fatal("SendSessionTicket on a client accepted")
	}
}

func contains(s []uint16, v uint16) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

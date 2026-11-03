// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package utls is a TLS client that controls the exact shape of the
// ClientHello (to match a browser's TLS fingerprint) while speaking the
// standard library's types everywhere else.
//
// The public API takes a standard *crypto/tls.Config and returns standard
// crypto/tls.ConnectionState values, so a uTLS connection plugs into net/http,
// x/net/http2 and the rest of the ecosystem. Internally, uTLS carries a
// mechanically synced copy of crypto/tls (see internal/ and upstream/).
//
//	conn, err := utls.Dial("tcp", "example.com:443", &tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
//
// or wrap an existing net.Conn:
//
//	uc := utls.UClient(rawConn, &tls.Config{ServerName: host}, utls.HelloChrome_Auto)
//	err := uc.HandshakeContext(ctx)
//
// The rules for how a fingerprint (ClientHelloSpec) and the Config combine are
// documented on ClientHelloSpec and in docs/API_DESIGN.md.
package utls

import (
	"crypto/tls"
	"errors"

	itls "github.com/refraction-networking/utls/internal/tls"
)

// ConnectionState is the standard library's crypto/tls.ConnectionState.
type ConnectionState = tls.ConnectionState

// CurveID names a TLS named group (same values as crypto/tls.CurveID).
type CurveID = itls.CurveID

// SignatureScheme names a TLS signature scheme (same values as crypto/tls).
type SignatureScheme = itls.SignatureScheme

// fromStdConfig converts a standard *crypto/tls.Config for the internal
// handshake. Every exported field is either converted here or listed with a
// reason in config_fields_test.go (which fails when a Go release adds one);
// behavior is covered by config_behavior_test.go.
func fromStdConfig(c *tls.Config) *itls.Config {
	if c == nil {
		return &itls.Config{}
	}
	c = c.Clone()
	ic := &itls.Config{
		Rand:                           c.Rand,
		Time:                           c.Time,
		RootCAs:                        c.RootCAs,
		NextProtos:                     c.NextProtos,
		ServerName:                     c.ServerName,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		CipherSuites:                   c.CipherSuites,
		SessionTicketsDisabled:         c.SessionTicketsDisabled,
		MinVersion:                     c.MinVersion,
		MaxVersion:                     c.MaxVersion,
		DynamicRecordSizingDisabled:    c.DynamicRecordSizingDisabled,
		KeyLogWriter:                   c.KeyLogWriter,
		VerifyPeerCertificate:          c.VerifyPeerCertificate,
		Renegotiation:                  itls.RenegotiationSupport(c.Renegotiation),
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
	}
	for _, g := range c.CurvePreferences {
		ic.CurvePreferences = append(ic.CurvePreferences, itls.CurveID(g))
	}
	for i := range c.Certificates {
		ic.Certificates = append(ic.Certificates, stdToInternalCertificate(c.Certificates[i]))
	}
	if c.ClientSessionCache != nil {
		ic.ClientSessionCache = stdSessionCache{c.ClientSessionCache}
	}
	if vc := c.VerifyConnection; vc != nil {
		ic.VerifyConnection = func(ics itls.ConnectionState) error { return vc(toStdConnectionState(ics)) }
	}
	if rv := c.EncryptedClientHelloRejectionVerify; rv != nil {
		ic.EncryptedClientHelloRejectionVerify = func(ics itls.ConnectionState) error { return rv(toStdConnectionState(ics)) }
	}
	if gcc := c.GetClientCertificate; gcc != nil {
		ic.GetClientCertificate = func(cri *itls.CertificateRequestInfo) (*itls.Certificate, error) {
			std, err := gcc(toStdCertificateRequestInfo(cri))
			if err != nil {
				return nil, err
			}
			if std == nil {
				std = &tls.Certificate{} // crypto/tls: an empty certificate sends none
			}
			ic := stdToInternalCertificate(*std)
			return &ic, nil
		}
	}
	return ic
}

func stdToInternalCertificate(c tls.Certificate) itls.Certificate {
	return itls.Certificate{
		Certificate:                  c.Certificate,
		PrivateKey:                   c.PrivateKey,
		SupportedSignatureAlgorithms: convertSigSchemes(c.SupportedSignatureAlgorithms),
		OCSPStaple:                   c.OCSPStaple,
		SignedCertificateTimestamps:  c.SignedCertificateTimestamps,
		Leaf:                         c.Leaf,
	}
}

func convertSigSchemes[T ~uint16](in []T) []itls.SignatureScheme {
	if in == nil {
		return nil
	}
	out := make([]itls.SignatureScheme, len(in))
	for i, v := range in {
		out[i] = itls.SignatureScheme(v)
	}
	return out
}

// toStdConnectionState converts the internal ConnectionState (see
// internal/tls/u_stdcompat.go for the exporter bridge).
func toStdConnectionState(cs itls.ConnectionState) tls.ConnectionState {
	return itls.StdConnectionState(cs)
}

func toStdCertificateRequestInfo(cri *itls.CertificateRequestInfo) *tls.CertificateRequestInfo {
	if cri == nil {
		return nil
	}
	return itls.StdCertificateRequestInfo(cri)
}

// configError reports Config features this build cannot honor faithfully,
// before any I/O.
func configError(c *tls.Config) error {
	if c != nil && c.GetClientCertificate != nil && !itls.StdContextBridgeOK() {
		return errors.New("utls: GetClientCertificate is unsupported with this Go release (CertificateRequestInfo.Context cannot be provided); see internal/tls/u_stdcompat.go")
	}
	return nil
}

func stdSigSchemes(in []itls.SignatureScheme) []tls.SignatureScheme {
	if in == nil {
		return nil
	}
	out := make([]tls.SignatureScheme, len(in))
	for i, v := range in {
		out[i] = tls.SignatureScheme(v)
	}
	return out
}

// stdSessionCache adapts a standard tls.ClientSessionCache. Sessions cross the
// boundary through crypto/tls's public, versioned session encoding
// (ClientSessionState.ResumptionState, SessionState.Bytes, ParseSessionState
// and NewResumptionState), so one cache can be shared with crypto/tls clients.
// A session that cannot be converted is treated as a cache miss.
type stdSessionCache struct{ std tls.ClientSessionCache }

func (s stdSessionCache) Get(key string) (*itls.ClientSessionState, bool) {
	cs, ok := s.std.Get(key)
	if !ok || cs == nil {
		return nil, false
	}
	ics, err := stdToInternalSession(cs)
	if err != nil {
		return nil, false
	}
	return ics, true
}

func (s stdSessionCache) Put(key string, cs *itls.ClientSessionState) {
	if cs == nil {
		s.std.Put(key, nil)
		return
	}
	std, err := internalToStdSession(cs)
	if err != nil {
		return
	}
	s.std.Put(key, std)
}

func stdToInternalSession(cs *tls.ClientSessionState) (*itls.ClientSessionState, error) {
	ticket, st, err := cs.ResumptionState()
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errNoSession
	}
	b, err := st.Bytes()
	if err != nil {
		return nil, err
	}
	ist, err := itls.ParseSessionState(b)
	if err != nil {
		return nil, err
	}
	return itls.NewResumptionState(ticket, ist)
}

var errNoSession = errors.New("utls: session state is empty")

func internalToStdSession(cs *itls.ClientSessionState) (*tls.ClientSessionState, error) {
	ticket, st, err := cs.ResumptionState()
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, errNoSession
	}
	b, err := st.Bytes()
	if err != nil {
		return nil, err
	}
	sst, err := tls.ParseSessionState(b)
	if err != nil {
		return nil, err
	}
	return tls.NewResumptionState(ticket, sst)
}


// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package utls is a drop-in TLS client that lets you control the exact bytes of
// the ClientHello — to mimic a browser's TLS fingerprint — while speaking to
// the standard library everywhere else.
//
// The design goal is maintainability across Go releases. uTLS carries a
// mechanically-synced copy of crypto/tls internally (see internal/ and
// upstream/), but the public API you import here is hand-written and stable: it
// takes the standard *crypto/tls.Config and returns the standard
// crypto/tls.ConnectionState, so a uTLS connection plugs into net/http,
// x/net/http2 and the rest of the ecosystem without type juggling.
//
// Start with a fingerprint and a dialer:
//
//	conn, err := utls.Dial("tcp", "example.com:443", &tls.Config{ServerName: "example.com"}, utls.HelloChrome_Auto)
//
// or wrap an existing net.Conn:
//
//	uc := utls.UClient(rawConn, &tls.Config{ServerName: host}, utls.HelloChrome_Auto)
//	err := uc.Handshake()
package utls

import (
	"crypto/tls"
	"crypto/x509"

	itls "github.com/refraction-networking/utls/internal/tls"
)

// ConnectionState is the standard library's crypto/tls.ConnectionState. uTLS
// deliberately returns the standard type so connections interoperate with
// net/http and anything else that inspects TLS state.
type ConnectionState = tls.ConnectionState

// CurveID names a TLS named group. It is uTLS's own type (identical in value
// to crypto/tls.CurveID) because the extension types a spec is built from use
// it; convert to/from crypto/tls.CurveID with ordinary uint16 conversion.
type CurveID = itls.CurveID

// SignatureScheme names a TLS signature scheme, uTLS's own type for the same
// reason as CurveID.
type SignatureScheme = itls.SignatureScheme

// fromStdConfig converts a standard *crypto/tls.Config into the internal config
// the mirrored handshake uses. It copies every client-relevant field; the
// fields it does not carry over are enumerated (and justified) in
// config_fields_test.go, whose reflection test fails if crypto/tls grows a
// field this converter has not considered. That turns a silent drop into a
// caught-at-CI error — the maintainability guarantee behind the v2 redesign.
func fromStdConfig(c *tls.Config) *itls.Config {
	if c == nil {
		return &itls.Config{}
	}
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
		ClientAuth:                     itls.ClientAuthType(c.ClientAuth),
		ClientCAs:                      c.ClientCAs,
		PreferServerCipherSuites:       c.PreferServerCipherSuites,
		Renegotiation:                  itls.RenegotiationSupport(c.Renegotiation),
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
	}
	// CurvePreferences: []tls.CurveID and []itls.CurveID are distinct named
	// types over uint16; convert elementwise.
	if len(c.CurvePreferences) > 0 {
		ic.CurvePreferences = make([]itls.CurveID, len(c.CurvePreferences))
		for i, g := range c.CurvePreferences {
			ic.CurvePreferences[i] = itls.CurveID(g)
		}
	}
	// Client certificates.
	if len(c.Certificates) > 0 {
		ic.Certificates = make([]itls.Certificate, len(c.Certificates))
		for i := range c.Certificates {
			ic.Certificates[i] = stdToInternalCertificate(c.Certificates[i])
		}
	}
	// Callbacks that take uTLS-typed arguments are wrapped so a caller's
	// standard-typed callback still works.
	if c.VerifyConnection != nil {
		vc := c.VerifyConnection
		ic.VerifyConnection = func(ics itls.ConnectionState) error {
			return vc(toStdConnectionState(ics))
		}
	}
	if c.GetClientCertificate != nil {
		gcc := c.GetClientCertificate
		ic.GetClientCertificate = func(cri *itls.CertificateRequestInfo) (*itls.Certificate, error) {
			std, err := gcc(toStdCertificateRequestInfo(cri))
			if err != nil {
				return nil, err
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

// toStdConnectionState converts the internal ConnectionState to the standard
// one. Fields are enumerated in config_fields_test.go with the same CI guard.
func toStdConnectionState(cs itls.ConnectionState) tls.ConnectionState {
	// NOTE: ExportKeyingMaterial on the returned value will not work: the
	// exporter is held in an unexported field that cannot be copied across the
	// type boundary. Call (*utls.UConn).ExportKeyingMaterial instead.
	return tls.ConnectionState{
		Version:                     cs.Version,
		HandshakeComplete:           cs.HandshakeComplete,
		DidResume:                   cs.DidResume,
		CipherSuite:                 cs.CipherSuite,
		CurveID:                     tls.CurveID(cs.CurveID),
		NegotiatedProtocol:          cs.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  cs.NegotiatedProtocolIsMutual,
		ServerName:                  cs.ServerName,
		PeerCertificates:            cs.PeerCertificates,
		VerifiedChains:              cs.VerifiedChains,
		SignedCertificateTimestamps: cs.SignedCertificateTimestamps,
		OCSPResponse:                cs.OCSPResponse,
		TLSUnique:                   cs.TLSUnique,
		ECHAccepted:                 cs.ECHAccepted,
		HelloRetryRequest:           cs.HelloRetryRequest,
		LocalCertificate:            cs.LocalCertificate,
	}
}

func toStdCertificateRequestInfo(cri *itls.CertificateRequestInfo) *tls.CertificateRequestInfo {
	if cri == nil {
		return nil
	}
	return &tls.CertificateRequestInfo{
		AcceptableCAs:    cri.AcceptableCAs,
		SignatureSchemes: stdSigSchemes(cri.SignatureSchemes),
		Version:          cri.Version,
	}
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

var _ = x509.NewCertPool

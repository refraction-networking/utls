// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

// Standard-type bridge: the ONLY place uTLS touches unexported fields of
// crypto/tls types (the narrow exception to "all coupling to the standard
// library lives in internal/tls").
//
// The public API returns crypto/tls types. Two of their behaviors depend on
// unexported fields that no public crypto/tls API sets:
//
//   - ConnectionState.ExportKeyingMaterial calls the unexported ekm field;
//   - CertificateRequestInfo.Context returns the unexported ctx field.
//
// StdConnectionState and StdCertificateRequestInfo set exactly those fields by
// name after checking their exact types (reflect + unsafe.Pointer on that one
// field; no struct layout is assumed). Supported: Go 1.27.x (checked by
// TestStdBridgeLayout on every Go release CI runs). If a future release renames
// or retypes a field:
//
//   - ConnectionState falls back to a value built by crypto/tls itself whose
//     ExportKeyingMaterial returns an error (never a nil-function panic); use
//     (*UConn).ExportKeyingMaterial, which never depends on the bridge.
//   - CertificateRequestInfo: StdContextBridgeOK reports false and the public
//     package rejects a Config with GetClientCertificate before any I/O,
//     instead of handing the callback a nil Context.

import (
	"context"
	stdtls "crypto/tls"
	"errors"
	"net"
	"reflect"
	"unsafe"
)

type ekmFunc = func(label string, context []byte, length int) ([]byte, error)

var (
	stdEKMOK = stdFieldIs(reflect.TypeOf(stdtls.ConnectionState{}), "ekm", reflect.TypeOf(ekmFunc(nil)))
	stdCtxOK = stdFieldIs(reflect.TypeOf(stdtls.CertificateRequestInfo{}), "ctx", reflect.TypeOf((*context.Context)(nil)).Elem())
)

func stdFieldIs(t reflect.Type, name string, want reflect.Type) bool {
	f, ok := t.FieldByName(name)
	return ok && !f.IsExported() && f.Type == want
}

func setStdField(ptr any, name string, val reflect.Value) {
	f := reflect.ValueOf(ptr).Elem().FieldByName(name)
	reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem().Set(val)
}

// StdBridgeStatus reports whether each bridged field matched (for tests and
// diagnostics).
func StdBridgeStatus() (exporter, context bool) { return stdEKMOK, stdCtxOK }

// SetStdBridgeForTest overrides the layout checks to exercise fallbacks.
func SetStdBridgeForTest(exporter, context bool) (restore func()) {
	e, c := stdEKMOK, stdCtxOK
	stdEKMOK, stdCtxOK = exporter, context
	return func() { stdEKMOK, stdCtxOK = e, c }
}

// StdContextBridgeOK reports whether CertificateRequestInfo.Context can be set.
func StdContextBridgeOK() bool { return stdCtxOK }

// ErrExporterUnavailable is returned by a bridged ConnectionState's exporter
// when no keying material can be exported yet (before the handshake completes).
var ErrExporterUnavailable = errorString("utls: keying material is not available (handshake not complete); use (*UConn).ExportKeyingMaterial")

type errorString string

func (e errorString) Error() string { return string(e) }

// StdConnectionState converts cs to the standard type with a working exporter.
func StdConnectionState(cs ConnectionState) stdtls.ConnectionState {
	var std stdtls.ConnectionState
	if stdEKMOK {
		ekm := cs.ekm
		if ekm == nil {
			ekm = func(string, []byte, int) ([]byte, error) { return nil, ErrExporterUnavailable }
		}
		setStdField(&std, "ekm", reflect.ValueOf(ekm))
	} else {
		// crypto/tls installs an always-erroring exporter on the state of a
		// connection that allows renegotiation; start from that value.
		std = stdtls.Client(nopNetConn{}, &stdtls.Config{Renegotiation: stdtls.RenegotiateOnceAsClient}).ConnectionState()
	}
	std.Version = cs.Version
	std.HandshakeComplete = cs.HandshakeComplete
	std.DidResume = cs.DidResume
	std.CipherSuite = cs.CipherSuite
	std.CurveID = stdtls.CurveID(cs.CurveID)
	std.NegotiatedProtocol = cs.NegotiatedProtocol
	std.NegotiatedProtocolIsMutual = cs.NegotiatedProtocolIsMutual
	std.ServerName = cs.ServerName
	std.PeerCertificates = cs.PeerCertificates
	std.VerifiedChains = cs.VerifiedChains
	std.SignedCertificateTimestamps = cs.SignedCertificateTimestamps
	std.OCSPResponse = cs.OCSPResponse
	std.TLSUnique = cs.TLSUnique
	std.ECHAccepted = cs.ECHAccepted
	std.HelloRetryRequest = cs.HelloRetryRequest
	std.LocalCertificate = cs.LocalCertificate
	return std
}

// StdCertificateRequestInfo converts cri to the standard type with its handshake
// context. Callers must check StdContextBridgeOK before relying on it.
func StdCertificateRequestInfo(cri *CertificateRequestInfo) *stdtls.CertificateRequestInfo {
	out := &stdtls.CertificateRequestInfo{AcceptableCAs: cri.AcceptableCAs, Version: cri.Version}
	for _, s := range cri.SignatureSchemes {
		out.SignatureSchemes = append(out.SignatureSchemes, stdtls.SignatureScheme(s))
	}
	if stdCtxOK && cri.ctx != nil {
		ctx := cri.ctx
		setStdField(out, "ctx", reflect.ValueOf(&ctx).Elem())
	}
	return out
}

type nopNetConn struct{ net.Conn }

// StdError maps errors of the mirrored package's exported error types to the
// crypto/tls types callers check with errors.As (ECHRejectionError,
// AlertError, CertificateVerificationError, RecordHeaderError). Other errors
// are returned unchanged.
func StdError(err error) error {
	if err == nil {
		return nil
	}
	std := stdErrorValue(err)
	if std == nil {
		return err
	}
	switch err.(type) {
	case *ECHRejectionError, *CertificateVerificationError, RecordHeaderError, AlertError:
		return std // the error is exactly the mapped value
	}
	// The mapped value is wrapped (e.g. a QUIC error wrapping the cause and an
	// AlertError): keep the original chain for errors.Is/As on the cause.
	return &stdWrappedError{err: err, std: std}
}

func stdErrorValue(err error) error {
	var ech *ECHRejectionError
	if errors.As(err, &ech) {
		return &stdtls.ECHRejectionError{RetryConfigList: ech.RetryConfigList}
	}
	var cv *CertificateVerificationError
	if errors.As(err, &cv) {
		return &stdtls.CertificateVerificationError{UnverifiedCertificates: cv.UnverifiedCertificates, Err: cv.Err}
	}
	var rh RecordHeaderError
	if errors.As(err, &rh) {
		return stdtls.RecordHeaderError{Msg: rh.Msg, RecordHeader: rh.RecordHeader, Conn: rh.Conn}
	}
	var ae AlertError
	if errors.As(err, &ae) {
		return stdtls.AlertError(ae)
	}
	return nil
}

// stdWrappedError has the message of err and unwraps to the crypto/tls value
// first, then to err's own chain.
type stdWrappedError struct {
	err, std error
}

func (e *stdWrappedError) Error() string   { return e.err.Error() }
func (e *stdWrappedError) Unwrap() []error { return []error{e.std, e.err} }

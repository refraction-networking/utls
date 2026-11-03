// Copyright 2024 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"crypto/tls"
	"reflect"
	"testing"

	itls "github.com/refraction-networking/utls/internal/tls"
)

// These tests are the maintainability guardrail for the crypto/tls interop
// boundary. When a new Go release adds a field to tls.Config or
// tls.ConnectionState, the matching test fails and names the field, forcing a
// decision in config.go instead of letting it be silently dropped. This is the
// mechanism that replaces downstream's reflection whitelists and field-by-field
// copies from the v1 era.

// configFieldsHandled lists every exported tls.Config field and how the
// converter treats it. "converted" fields are carried into the internal config;
// "unsupported" fields are intentionally not (with a reason). A field in
// neither set (i.e. a newly added one) fails the test.
var configFieldsHandled = map[string]string{
	// Carried across by fromStdConfig:
	"Rand":                                "converted",
	"Time":                                "converted",
	"Certificates":                        "converted",
	"GetClientCertificate":                "converted (wrapped)",
	"VerifyPeerCertificate":               "converted",
	"VerifyConnection":                    "converted (wrapped)",
	"RootCAs":                             "converted",
	"NextProtos":                          "converted",
	"ServerName":                          "converted",
	"ClientAuth":                          "unsupported: server-side",
	"ClientCAs":                           "unsupported: server-side",
	"InsecureSkipVerify":                  "converted",
	"CipherSuites":                        "converted",
	"PreferServerCipherSuites":            "unsupported: deprecated server-side field",
	"SessionTicketsDisabled":              "converted",
	"MinVersion":                          "converted",
	"MaxVersion":                          "converted",
	"CurvePreferences":                    "converted",
	"DynamicRecordSizingDisabled":         "converted",
	"Renegotiation":                       "converted",
	"KeyLogWriter":                        "converted",
	"EncryptedClientHelloConfigList":      "converted",
	"ClientSessionCache":                  "converted (bridged via the public session encoding)",
	"EncryptedClientHelloRejectionVerify": "converted (wrapped)",

	// Intentionally not carried across (document why):
	"NameToCertificate":           "unsupported: deprecated server field, unused by clients",
	"GetCertificate":              "unsupported: server-side callback",
	"GetConfigForClient":          "unsupported: server-side callback",
	"SessionTicketKey":            "unsupported: server-side ticket key",
	"UnwrapSession":               "unsupported: server-side session wrapping",
	"WrapSession":                 "unsupported: server-side session wrapping",
	"GetEncryptedClientHelloKeys": "unsupported: server-side ECH",
	"EncryptedClientHelloKeys":    "unsupported: server-side ECH",
}

func TestConfigFieldsConsidered(t *testing.T) {
	rt := reflect.TypeOf(tls.Config{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		if _, ok := configFieldsHandled[f.Name]; !ok {
			t.Errorf("tls.Config.%s is new and unhandled by fromStdConfig: add it to config.go and configFieldsHandled (converted or, with a reason, unsupported)", f.Name)
		}
	}
	// Reverse: don't let the map reference a field that no longer exists.
	for name := range configFieldsHandled {
		if _, ok := rt.FieldByName(name); !ok {
			t.Errorf("configFieldsHandled references tls.Config.%s, which no longer exists", name)
		}
	}
}

var connStateFieldsHandled = map[string]bool{
	"Version": true, "HandshakeComplete": true, "DidResume": true,
	"CipherSuite": true, "CurveID": true, "NegotiatedProtocol": true,
	"NegotiatedProtocolIsMutual": true, "ServerName": true,
	"PeerCertificates": true, "VerifiedChains": true,
	"SignedCertificateTimestamps": true, "OCSPResponse": true,
	"TLSUnique": true, "ECHAccepted": true, "HelloRetryRequest": true,
	"LocalCertificate": true,
	// ekm is unexported and intentionally not bridged (documented in config.go).
}

func TestConnectionStateFieldsConsidered(t *testing.T) {
	rt := reflect.TypeOf(tls.ConnectionState{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !f.IsExported() {
			continue
		}
		if !connStateFieldsHandled[f.Name] {
			t.Errorf("tls.ConnectionState.%s is new and unhandled by toStdConnectionState: add it to config.go and connStateFieldsHandled", f.Name)
		}
	}
}

// The internal mirror's Config/ConnectionState must stay field-identical to the
// Go release it was synced from, so the converter's assumptions hold.
func TestInternalMirrorMatchesStdlib(t *testing.T) {
	assertSameExportedFields(t, "Config", reflect.TypeOf(tls.Config{}), reflect.TypeOf(itls.Config{}))
	assertSameExportedFields(t, "ConnectionState", reflect.TypeOf(tls.ConnectionState{}), reflect.TypeOf(itls.ConnectionState{}))
}

func assertSameExportedFields(t *testing.T, name string, std, mirror reflect.Type) {
	t.Helper()
	exported := func(rt reflect.Type) map[string]bool {
		m := map[string]bool{}
		for i := 0; i < rt.NumField(); i++ {
			if f := rt.Field(i); f.IsExported() {
				m[f.Name] = true
			}
		}
		return m
	}
	s, mi := exported(std), exported(mirror)
	for f := range s {
		if !mi[f] {
			t.Errorf("%s: crypto/tls has exported field %s that the internal mirror lacks; re-run upstream/sync.sh", name, f)
		}
	}
	for f := range mi {
		if !s[f] {
			t.Errorf("%s: internal mirror has exported field %s not in crypto/tls; a [uTLS] change leaked into a mirrored type", name, f)
		}
	}
}

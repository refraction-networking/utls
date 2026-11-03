// Copyright 2026 The uTLS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package utls

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

// Profile is a fingerprint stored as JSON, so fingerprints can be shipped and
// updated as data. The format is versioned:
//
//	{
//	  "format": "utls-profile",
//	  "version": 1,
//	  "client": "MyBrowser", "client_version": "1",
//	  "shuffle": "chrome",                 // optional: permute per connection
//	  "tls_vers_min": 771, "tls_vers_max": 772,
//	  "cipher_suites": [2570, 4865, ...],   // 2570 (0x0a0a) = GREASE
//	  "compression_methods": [0],
//	  "extensions": [
//	    {"type": "grease"},
//	    {"type": "server_name"},
//	    {"type": "supported_groups", "params": {"Curves": [2570, 4588, 29, 23, 24]}},
//	    {"type": "padding", "params": {"style": "boringssl"}},
//	    {"type": "generic", "params": {"Id": 17513, "Data": "AAMCaDI="}},
//	    ...
//	  ]
//	}
//
// "params" holds the exported fields of the corresponding extension type
// (byte strings in base64, as encoding/json does). Parsing is strict: an
// unknown format, version, field or extension type is an error, never
// silently dropped, and the result must pass ClientHelloSpec.Validate.
type Profile struct {
	Client  string
	Version string
	// Shuffle is "" (fixed order) or "chrome" (Chrome's per-connection
	// extension permutation, keeping GREASE, padding and pre_shared_key
	// in place).
	Shuffle string
	Spec    *ClientHelloSpec
}

// ProfileFormat and ProfileVersion identify the JSON format this package
// reads and writes.
const (
	ProfileFormat  = "utls-profile"
	ProfileVersion = 1
)

type profileJSON struct {
	Format             string       `json:"format"`
	Version            int          `json:"version"`
	Client             string       `json:"client"`
	ClientVersion      string       `json:"client_version"`
	Shuffle            string       `json:"shuffle,omitempty"`
	TLSVersMin         uint16       `json:"tls_vers_min,omitempty"`
	TLSVersMax         uint16       `json:"tls_vers_max,omitempty"`
	CipherSuites       []uint16     `json:"cipher_suites"`
	CompressionMethods []int        `json:"compression_methods"`
	Extensions         []profileExt `json:"extensions"`
}

type profileExt struct {
	Type   string          `json:"type"`
	Params json.RawMessage `json:"params,omitempty"`
}

type paddingParams struct {
	Style string `json:"style"`
}

// profileTypes maps profile type names to extension types.
var profileTypes = map[string]reflect.Type{
	"server_name":                  reflect.TypeFor[SNIExtension](),
	"supported_versions":           reflect.TypeFor[SupportedVersionsExtension](),
	"supported_groups":             reflect.TypeFor[SupportedCurvesExtension](),
	"ec_point_formats":             reflect.TypeFor[SupportedPointsExtension](),
	"signature_algorithms":         reflect.TypeFor[SignatureAlgorithmsExtension](),
	"signature_algorithms_cert":    reflect.TypeFor[SignatureAlgorithmsCertExtension](),
	"alpn":                         reflect.TypeFor[ALPNExtension](),
	"application_settings":         reflect.TypeFor[ApplicationSettingsExtension](),
	"status_request":               reflect.TypeFor[StatusRequestExtension](),
	"signed_certificate_timestamp": reflect.TypeFor[SCTExtension](),
	"extended_master_secret":       reflect.TypeFor[ExtendedMasterSecretExtension](),
	"renegotiation_info":           reflect.TypeFor[RenegotiationInfoExtension](),
	"session_ticket":               reflect.TypeFor[SessionTicketExtension](),
	"psk_key_exchange_modes":       reflect.TypeFor[PSKKeyExchangeModesExtension](),
	"compress_certificate":         reflect.TypeFor[CompressCertificateExtension](),
	"record_size_limit":            reflect.TypeFor[RecordSizeLimitExtension](),
	"key_share":                    reflect.TypeFor[KeyShareExtension](),
	"encrypted_client_hello":       reflect.TypeFor[EncryptedClientHelloExtension](),
	"pre_shared_key":               reflect.TypeFor[PreSharedKeyExtension](),
	"early_data":                   reflect.TypeFor[EarlyDataExtension](),
	"cookie":                       reflect.TypeFor[CookieExtension](),
	"quic_transport_parameters":    reflect.TypeFor[QUICTransportParametersExtension](),
	"trust_anchors":                reflect.TypeFor[TrustAnchorsExtension](),
	"grease":                       reflect.TypeFor[UtlsGREASEExtension](),
	"generic":                      reflect.TypeFor[GenericExtension](),
	"padding":                      reflect.TypeFor[UtlsPaddingExtension](),
}

var profileNames = func() map[reflect.Type]string {
	m := map[reflect.Type]string{}
	for n, t := range profileTypes {
		m[t] = n
	}
	return m
}()

// MarshalJSON encodes the profile in the current format.
func (p *Profile) MarshalJSON() ([]byte, error) {
	if p.Spec == nil {
		return nil, errors.New("utls: profile has no spec")
	}
	if err := p.Spec.Validate(); err != nil {
		return nil, err
	}
	if p.Shuffle != "" && p.Shuffle != "chrome" {
		return nil, fmt.Errorf("utls: unknown profile shuffle %q", p.Shuffle)
	}
	out := profileJSON{
		Format: ProfileFormat, Version: ProfileVersion,
		Client: p.Client, ClientVersion: p.Version, Shuffle: p.Shuffle,
		TLSVersMin: p.Spec.TLSVersMin, TLSVersMax: p.Spec.TLSVersMax,
		CipherSuites: p.Spec.CipherSuites,
	}
	for _, m := range p.Spec.CompressionMethods {
		out.CompressionMethods = append(out.CompressionMethods, int(m))
	}
	for _, e := range p.Spec.Extensions {
		v := reflect.ValueOf(e)
		name, ok := profileNames[v.Type().Elem()]
		if !ok {
			return nil, fmt.Errorf("utls: extension type %T cannot be stored in a profile", e)
		}
		pe := profileExt{Type: name}
		var params any = e
		if pad, ok := e.(*UtlsPaddingExtension); ok {
			if pad.GetPaddingLen != nil && reflect.ValueOf(pad.GetPaddingLen).Pointer() != reflect.ValueOf(BoringPaddingStyle).Pointer() {
				return nil, errors.New("utls: only BoringPaddingStyle padding can be stored in a profile")
			}
			params = paddingParams{Style: "boringssl"}
		}
		if v.Elem().NumField() > 0 || name == "padding" {
			b, err := json.Marshal(params)
			if err != nil {
				return nil, err
			}
			pe.Params = b
		}
		out.Extensions = append(out.Extensions, pe)
	}
	return json.MarshalIndent(out, "", "  ")
}

// UnmarshalJSON decodes and validates a profile.
func (p *Profile) UnmarshalJSON(data []byte) error {
	var in profileJSON
	if err := strictUnmarshal(data, &in); err != nil {
		return fmt.Errorf("utls: profile: %w", err)
	}
	if in.Format != ProfileFormat {
		return fmt.Errorf("utls: profile format %q, want %q", in.Format, ProfileFormat)
	}
	if in.Version != ProfileVersion {
		return fmt.Errorf("utls: profile version %d is not supported (this uTLS reads version %d)", in.Version, ProfileVersion)
	}
	if in.Shuffle != "" && in.Shuffle != "chrome" {
		return fmt.Errorf("utls: unknown profile shuffle %q", in.Shuffle)
	}
	spec := &ClientHelloSpec{CipherSuites: in.CipherSuites, TLSVersMin: in.TLSVersMin, TLSVersMax: in.TLSVersMax}
	for _, m := range in.CompressionMethods {
		if m < 0 || m > 255 {
			return fmt.Errorf("utls: profile compression method %d out of range", m)
		}
		spec.CompressionMethods = append(spec.CompressionMethods, uint8(m))
	}
	for i, pe := range in.Extensions {
		t, ok := profileTypes[pe.Type]
		if !ok {
			return fmt.Errorf("utls: profile extension %d: unknown type %q", i, pe.Type)
		}
		v := reflect.New(t)
		if pe.Type == "padding" {
			var pp paddingParams
			if len(pe.Params) > 0 {
				if err := strictUnmarshal(pe.Params, &pp); err != nil {
					return fmt.Errorf("utls: profile extension %d (padding): %w", i, err)
				}
			}
			if pp.Style != "boringssl" {
				return fmt.Errorf("utls: profile extension %d: unknown padding style %q", i, pp.Style)
			}
			v.Interface().(*UtlsPaddingExtension).GetPaddingLen = BoringPaddingStyle
		} else if len(pe.Params) > 0 {
			if t.NumField() == 0 {
				return fmt.Errorf("utls: profile extension %d (%s) takes no params", i, pe.Type)
			}
			if err := strictUnmarshal(pe.Params, v.Interface()); err != nil {
				return fmt.Errorf("utls: profile extension %d (%s): %w", i, pe.Type, err)
			}
		}
		spec.Extensions = append(spec.Extensions, v.Interface().(TLSExtension))
	}
	if err := spec.Validate(); err != nil {
		return fmt.Errorf("utls: profile: %w", err)
	}
	*p = Profile{Client: in.Client, Version: in.ClientVersion, Shuffle: in.Shuffle, Spec: spec}
	return nil
}

func strictUnmarshal(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

// ParseProfile parses a JSON profile.
func ParseProfile(data []byte) (*Profile, error) {
	p := new(Profile)
	if err := p.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return p, nil
}

// ClientHelloID returns a fingerprint that sends a fresh copy of the
// profile's spec (shuffled per connection if Shuffle is "chrome"). Each call
// returns a distinct ClientHelloID.
func (p *Profile) ClientHelloID() ClientHelloID {
	spec := p.Spec.Clone()
	shuffle := p.Shuffle == "chrome"
	return CustomFingerprint(p.Client, p.Version, func() (*ClientHelloSpec, error) {
		if spec == nil {
			return nil, errors.New("utls: profile has no spec")
		}
		s := spec.Clone()
		if shuffle {
			s.Extensions = shuffleChromeExtensions(s.Extensions)
		}
		return s, nil
	})
}

// ExportProfile returns the profile of a built-in or custom fingerprint. For
// shuffled presets (Chrome, Edge) the stored order is one permutation and
// Shuffle is "chrome".
func ExportProfile(id ClientHelloID) (*Profile, error) {
	spec, err := id.Spec()
	if err != nil {
		return nil, err
	}
	p := &Profile{Client: id.Client, Version: id.Version, Spec: spec}
	if id.Client == "Chrome" || id.Client == "Edge" {
		p.Shuffle = "chrome"
	}
	return p, nil
}
